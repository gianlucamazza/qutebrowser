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
        },
        {
            "id": "xyz",
            "title": "Other",
            "urls": [{"href": "https://other.com"}],
            "additional_information": "other@other.com",
        },
    ]
    backend = fake_op(items)
    results = backend.find_items("https://example.com/login")
    assert results[0]["id"] == "abc"
    assert results[0]["url_match_score"] == 1


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


def test_op_error_raises(fake_op):
    backend = fake_op({"error": "Unauthorized"}, returncode=1)
    with pytest.raises(OpCliError):
        backend.find_items("https://example.com")
