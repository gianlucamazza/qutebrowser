# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OpCliBackend using a fake `op` binary."""

import json
import os
import pathlib
import stat
import sys
import textwrap

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from sidecar.backends.op_cli import OpCliBackend, OpCliError


@pytest.fixture()
def fake_op(tmp_path, monkeypatch):
    """Return a helper that installs a fake `op` script and returns the backend."""

    def _install(stdout_json: object, returncode: int = 0):
        script = tmp_path / "op"
        payload = json.dumps(stdout_json)
        script.write_text(
            textwrap.dedent(f"""\
                #!/bin/sh
                echo '{payload}'
                exit {returncode}
            """)
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("PATH", str(tmp_path) + ":" + os.environ.get("PATH", ""))
        return OpCliBackend()

    return _install


def test_find_items_returns_matching(fake_op):
    items = [
        {
            "id": "abc",
            "title": "Example",
            "urls": [{"href": "https://example.com"}],
            "additional_information": "user@example.com",
            "vault": {"name": "Private"},
        },
        {
            "id": "xyz",
            "title": "Other",
            "urls": [{"href": "https://other.com"}],
            "additional_information": "other@other.com",
            "vault": {"name": "Work"},
        },
    ]
    backend = fake_op(items)
    results = backend.find_items("https://example.com/login")
    assert results[0]["id"] == "abc"
    assert results[0]["url_match_score"] == 1
    assert results[0]["vault"] == "Private"


def test_find_items_no_match_returns_empty(fake_op):
    items = [
        {"id": "abc", "title": "Example", "urls": [], "additional_information": ""}
    ]
    backend = fake_op(items)
    results = backend.find_items("https://example.com/login")
    assert results == []


def test_find_items_rejects_substring_lookalike(fake_op):
    items = [
        {
            "id": "real-github",
            "title": "GitHub",
            "urls": [{"href": "https://github.com"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://evilgithub.com/login")
    assert results == []


def test_find_items_matches_subdomain(fake_op):
    items = [
        {
            "id": "github-main",
            "title": "GitHub",
            "urls": [{"href": "https://github.com"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://api.github.com/login")
    assert len(results) == 1
    assert results[0]["id"] == "github-main"


def test_find_items_matches_parent_when_item_is_subdomain(fake_op):
    items = [
        {
            "id": "login-google",
            "title": "Google",
            "urls": [{"href": "https://accounts.google.com"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://google.com/")
    assert len(results) == 1


def test_get_item_extracts_credentials(fake_op):
    raw = {
        "id": "abc",
        "fields": [
            {"purpose": "USERNAME", "value": "alice"},
            {"purpose": "PASSWORD", "value": "s3cret"},
        ],
    }
    backend = fake_op(raw)
    item = backend.get_item("abc")
    assert item["username"] == "alice"
    assert item["password"] == "s3cret"
    assert item["totp"] is None


def test_save_login_returns_id(fake_op):
    backend = fake_op({"id": "newid"})
    result = backend.save_login("https://example.com", "bob", "pass")
    assert result["id"] == "newid"


def test_find_items_matches_locale_subdomain(fake_op):
    # Item saved with locale-specific URL, page visited on main subdomain.
    # 'it-it.facebook.com' and 'www.facebook.com' share registrable domain
    # 'facebook.com' -> should match.
    items = [
        {
            "id": "fb",
            "title": "Facebook",
            "urls": [{"href": "https://it-it.facebook.com/"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://www.facebook.com/login")
    assert len(results) == 1
    assert results[0]["id"] == "fb"


def test_find_items_still_rejects_lookalike_with_registrable_domain(fake_op):
    # 'evilgithub.com' registrable domain != 'github.com' -> no match.
    items = [
        {
            "id": "real-github",
            "title": "GitHub",
            "urls": [{"href": "https://github.com"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://evilgithub.com/login")
    assert results == []


def test_op_error_raises(fake_op):
    backend = fake_op({"error": "Unauthorized"}, returncode=1)
    with pytest.raises(OpCliError):
        backend.find_items("https://example.com")


def test_find_items_rejects_cctld_collision(fake_op):
    # 'co.uk' is a public suffix: 'bar.co.uk' and 'baz.co.uk' are
    # distinct registrable domains. The old naive last-2-parts heuristic
    # would have falsely unified them on 'co.uk'.
    items = [
        {
            "id": "uk-bar",
            "title": "Bar UK",
            "urls": [{"href": "https://app.bar.co.uk"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://app.baz.co.uk/login")
    assert results == []


def test_find_items_rejects_public_paas_collision(fake_op):
    # 'herokuapp.com' is a public suffix in the PSL: two apps on the same
    # PaaS have DISTINCT registrable domains. This prevents credential
    # theft via a sibling subdomain on a shared public host.
    items = [
        {
            "id": "heroku-app1",
            "title": "My Heroku App",
            "urls": [{"href": "https://myapp.herokuapp.com"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://attacker.herokuapp.com/login")
    assert results == []


def test_find_items_rejects_github_pages_collision(fake_op):
    # 'github.io' is a public suffix: each GitHub Pages user has a distinct
    # eTLD+1 (alice.github.io vs bob.github.io).
    items = [
        {
            "id": "ghpages-alice",
            "title": "Alice site",
            "urls": [{"href": "https://alice.github.io"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    results = backend.find_items("https://bob.github.io/login")
    assert results == []


def test_find_items_localhost_matches_exactly(fake_op):
    items = [
        {
            "id": "local",
            "title": "Local dev",
            "urls": [{"href": "http://localhost:3000"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    assert len(backend.find_items("http://localhost:3000/login")) == 1


def test_find_items_ip_matches_exactly(fake_op):
    items = [
        {
            "id": "ip-item",
            "title": "Direct IP",
            "urls": [{"href": "http://192.168.1.10"}],
            "additional_information": "user",
        }
    ]
    backend = fake_op(items)
    assert len(backend.find_items("http://192.168.1.10/login")) == 1
    assert backend.find_items("http://192.168.1.11/login") == []
