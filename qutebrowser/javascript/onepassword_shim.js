// SPDX-FileCopyrightText: Gianluca
// SPDX-License-Identifier: GPL-3.0-or-later
//
// onepassword_shim.js — MainWorld, DocumentCreation
// Observes password-form submissions and asks the Python side to offer
// saving credentials to 1Password via QWebChannel.

(function () {
    "use strict";

    var _op = null; // the 'onepassword' QObject proxy, set once channel is ready

    // ------------------------------------------------------------------
    // QWebChannel bootstrap
    // ------------------------------------------------------------------

    function setupChannel() {
        if (typeof QWebChannel === "undefined" || !window.qt || !window.qt.webChannelTransport) {
            // qwebchannel.js or the transport may not be ready yet
            setTimeout(setupChannel, 50);
            return;
        }
        new QWebChannel(qt.webChannelTransport, function (ch) {
            _op = ch.objects.onepassword;
        });
    }

    // ------------------------------------------------------------------
    // Credential extraction
    // ------------------------------------------------------------------

    function extractCredentials(form) {
        var username = "";
        var password = "";
        var inputs = form.querySelectorAll("input");
        inputs.forEach(function (inp) {
            var t = (inp.type || "text").toLowerCase();
            if (t === "password" && inp.value && !password) {
                password = inp.value;
            } else if ((t === "text" || t === "email") && inp.value && !username) {
                username = inp.value;
            }
        });
        return { username: username, password: password };
    }

    // ------------------------------------------------------------------
    // Form submit observer (capture phase — fires before any handler)
    // ------------------------------------------------------------------

    document.addEventListener(
        "submit",
        function (e) {
            if (!_op) return;
            var form = e.target;
            if (!(form instanceof HTMLFormElement)) return;
            var creds = extractCredentials(form);
            if (!creds.password) return;
            _op.autosave_requested(
                window.location.href,
                creds.username,
                creds.password
            );
        },
        true // capture phase: fires before the form's own submit handlers
    );

    setupChannel();
})();
