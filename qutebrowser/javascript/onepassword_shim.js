// SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// onepassword_shim.js — MainWorld, DocumentCreation
// Observes password-form submissions (autosave) and optionally intercepts
// navigator.credentials.{get,create} for passkey support via QWebChannel.

"use strict";

(function() {
    let _op = null; // the 'onepassword' QObject proxy, set once channel is ready

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _b64urlToBuf(b64url) {
        let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4) {
            b64 += "=";
        }
        const bin = atob(b64);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            buf[i] = bin.charCodeAt(i);
        }
        return buf.buffer;
    }

    function _bufToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    function _mkReqId() {
        return (Math.random() * 0xffffffff >>> 0).toString(16) +
               (Math.random() * 0xffffffff >>> 0).toString(16);
    }

    // Pending passkey calls: reqId -> {resolve, reject}
    const _pending = {};

    // ------------------------------------------------------------------
    // QWebChannel bootstrap
    // ------------------------------------------------------------------

    function setupChannel() {
        if (typeof QWebChannel === "undefined" ||
                !window.qt || !window.qt.webChannelTransport) {
            setTimeout(setupChannel, 50);
            return;
        }
        new QWebChannel(qt.webChannelTransport, function(ch) {
            _op = ch.objects.onepassword;
            _setupPasskeyShim();
        });
    }

    // ------------------------------------------------------------------
    // Credential extraction (for autosave)
    // ------------------------------------------------------------------

    function extractCredentials(form) {
        let username = "";
        let password = "";
        const inputs = form.querySelectorAll("input");
        inputs.forEach(function(inp) {
            const t = (inp.type || "text").toLowerCase();
            if (t === "password" && inp.value && !password) {
                password = inp.value;
            } else if ((t === "text" || t === "email") && inp.value && !username) {
                username = inp.value;
            }
        });
        return {"username": username, "password": password};
    }

    // ------------------------------------------------------------------
    // Form submit observer (autosave — capture phase)
    // ------------------------------------------------------------------

    document.addEventListener(
        "submit",
        function(e) {
            if (!_op) {
                return;
            }
            const form = e.target;
            if (!(form instanceof HTMLFormElement)) {
                return;
            }
            const creds = extractCredentials(form);
            if (!creds.password) {
                return;
            }
            _op.autosave_requested(
                window.location.href,
                creds.username,
                creds.password,
            );
        },
        true,
    );

    // ------------------------------------------------------------------
    // Passkey shim — called once the QWebChannel is ready
    // ------------------------------------------------------------------

    function _setupPasskeyShim() {
        _op.capabilities(function(jsonCaps) {
            let caps;
            try {
                caps = JSON.parse(jsonCaps);
            } catch (e) {
                console.warn("[1Password] failed to parse capabilities:", e);
                return;
            }
            const hasGet = caps.indexOf("passkey_get") !== -1;
            const hasCreate = caps.indexOf("passkey_create") !== -1;
            if (!hasGet && !hasCreate) {
                console.debug("[1Password] passkey shim disabled (capability missing)");
                return;
            }

            // Connect signal handlers once
            _op.passkey_result.connect(_onPasskeyResult);
            _op.passkey_error.connect(_onPasskeyError);

            if (hasGet) {
                _patchCredentialsGet();
            }
            if (hasCreate) {
                _patchCredentialsCreate();
            }
        });

        // Re-evaluate if the backend reconnects with different capabilities
        _op.capabilities_changed.connect(function() {
            _setupPasskeyShim();
        });
    }

    function _onPasskeyResult(reqId, jsonBlob) {
        const p = _pending[reqId];
        if (!p) {
            return;
        }
        delete _pending[reqId];
        let blob;
        try {
            blob = JSON.parse(jsonBlob);
        } catch (e) {
            p.reject(new DOMException(
                "Invalid response from 1Password sidecar", "UnknownError",
            ));
            return;
        }
        p.resolve(blob);
    }

    function _onPasskeyError(reqId, msg) {
        const p = _pending[reqId];
        if (!p) {
            return;
        }
        delete _pending[reqId];
        p.reject(new DOMException(msg, "NotAllowedError"));
    }

    // ------------------------------------------------------------------
    // navigator.credentials.get patch
    // ------------------------------------------------------------------

    function _patchCredentialsGet() {
        const featurePolicy = document.featurePolicy || document.permissionsPolicy;
        if (featurePolicy && !featurePolicy.allowsFeature("publickey-credentials-get")) {
            console.debug(
                "[1Password] publickey-credentials-get blocked by policy; skipping patch",
            );
            return;
        }
        const _origGet = navigator.credentials.get.bind(navigator.credentials);
        try {
            Object.defineProperty(navigator.credentials, "get", {
                "configurable": true,
                "writable": true,
                "value": function(options) {
                    if (!options || !options.publicKey) {
                        return _origGet(options);
                    }
                    return new Promise(function(resolve, reject) {
                        const reqId = _mkReqId();
                        const pk = options.publicKey;
                        const params = {
                            "rp_id": pk.rpId || location.hostname,
                            "challenge": _bufToB64url(pk.challenge),
                            "allow_credentials": (pk.allowCredentials || []).map(
                                function(c) { return _bufToB64url(c.id); },
                            ),
                        };
                        _pending[reqId] = {
                            "resolve": function(blob) { resolve(_mkAssertionCred(blob)); },
                            "reject": reject,
                        };
                        _op.passkey_get(reqId, JSON.stringify(params));
                    });
                },
            });
        } catch (e) {
            console.warn("[1Password] passkey get patch failed:", e);
        }
    }

    // ------------------------------------------------------------------
    // navigator.credentials.create patch
    // ------------------------------------------------------------------

    function _patchCredentialsCreate() {
        const featurePolicy = document.featurePolicy || document.permissionsPolicy;
        if (featurePolicy &&
                !featurePolicy.allowsFeature("publickey-credentials-create")) {
            console.debug(
                "[1Password] publickey-credentials-create blocked by policy; skipping patch",
            );
            return;
        }
        const _origCreate = navigator.credentials.create.bind(navigator.credentials);
        try {
            Object.defineProperty(navigator.credentials, "create", {
                "configurable": true,
                "writable": true,
                "value": function(options) {
                    if (!options || !options.publicKey) {
                        return _origCreate(options);
                    }
                    return new Promise(function(resolve, reject) {
                        const reqId = _mkReqId();
                        const pk = options.publicKey;
                        const params = {
                            "rp_id": pk.rp ? pk.rp.id : location.hostname,
                            "user": {
                                "id": _bufToB64url(pk.user.id),
                                "name": pk.user.name,
                                "display_name": pk.user.displayName || pk.user.name,
                            },
                            "challenge": _bufToB64url(pk.challenge),
                            "pub_key_cred_params": (pk.pubKeyCredParams || []).map(
                                function(p) { return {"type": p.type, "alg": p.alg}; },
                            ),
                        };
                        _pending[reqId] = {
                            "resolve": function(blob) {
                                resolve(_mkAttestationCred(blob));
                            },
                            "reject": reject,
                        };
                        _op.passkey_create(reqId, JSON.stringify(params));
                    });
                },
            });
        } catch (e) {
            console.warn("[1Password] passkey create patch failed:", e);
        }
    }

    // ------------------------------------------------------------------
    // Build PublicKeyCredential-shaped plain objects
    // NOTE: instanceof PublicKeyCredential checks will fail on these objects.
    //       Sites that rely on instanceof may not work. This is a known
    //       limitation of the JS-shim approach; a future CDP-based approach
    //       would return real instances.
    // ------------------------------------------------------------------

    function _mkAssertionCred(blob) {
        const credId = _b64urlToBuf(blob.credential_id_b64);
        return {
            "id": blob.credential_id_b64,
            "rawId": credId,
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "response": {
                "clientDataJSON": _b64urlToBuf(blob.client_data_json_b64),
                "authenticatorData": _b64urlToBuf(blob.authenticator_data_b64),
                "signature": _b64urlToBuf(blob.signature_b64),
                "userHandle": blob.user_handle_b64
                    ? _b64urlToBuf(blob.user_handle_b64)
                    : null,
            },
            "getClientExtensionResults": function() { return {}; },
            "toJSON": function() { return this; },
        };
    }

    function _mkAttestationCred(blob) {
        const credId = _b64urlToBuf(blob.credential_id_b64);
        const attObj = _b64urlToBuf(blob.attestation_obj_b64);
        const cdJson = _b64urlToBuf(blob.client_data_json_b64);
        return {
            "id": blob.credential_id_b64,
            "rawId": credId,
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "response": {
                "clientDataJSON": cdJson,
                "attestationObject": attObj,
                "getAuthenticatorData": function() { return attObj; },
                "getPublicKey": function() { return null; },
                "getPublicKeyAlgorithm": function() { return -7; }, // ES256
                "getTransports": function() { return ["internal"]; },
            },
            "getClientExtensionResults": function() { return {}; },
            "toJSON": function() { return this; },
        };
    }

    setupChannel();
}());
