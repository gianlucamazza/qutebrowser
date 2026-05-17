# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for the 1Password completion model."""

import json
import subprocess

import pytest

from qutebrowser.completion.models import onepassword_model


def _make_op_result(items):
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(items), stderr=""
    )


def test_fetch_items_no_op_binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    assert onepassword_model._fetch_items("https://x.com") == []


def test_fetch_items_parses_op_output(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/op")
    items = [
        {
            "id": "abc123",
            "title": "GitHub",
            "fields": [{"purpose": "USERNAME", "value": "user@x.com"}],
        }
    ]
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _make_op_result(items),
    )
    result = onepassword_model._fetch_items("https://github.com")
    assert len(result) == 1
    item_id, title, username = result[0]
    assert item_id == "abc123"
    assert title == "GitHub"
    assert username == "user@x.com"


def test_fetch_items_timeout_returns_empty(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/op")

    def _raise(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="op", timeout=3)

    monkeypatch.setattr(subprocess, "run", _raise)
    assert onepassword_model._fetch_items("https://x.com") == []


def test_fetch_items_nonzero_returncode_returns_empty(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/op")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        ),
    )
    assert onepassword_model._fetch_items("https://x.com") == []


def test_fetch_items_invalid_json_returns_empty(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/op")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=[], returncode=0, stdout="not-json", stderr=""
        ),
    )
    assert onepassword_model._fetch_items("https://x.com") == []


def test_onepassword_items_model_returns_completionmodel(qapp, monkeypatch):
    monkeypatch.setattr(
        "qutebrowser.completion.models.onepassword_model._fetch_items",
        lambda url: [("id1", "GitHub", "user@x.com")],
    )
    fake_tab = type(
        "T",
        (),
        {
            "url": lambda self: type(
                "U", (), {"toString": lambda self: "https://github.com"}
            )()
        },
    )()
    info = type("I", (), {"cur_tab": fake_tab})()

    from qutebrowser.completion.models import completionmodel

    model = onepassword_model.onepassword_items(info=info)
    assert isinstance(model, completionmodel.CompletionModel)
