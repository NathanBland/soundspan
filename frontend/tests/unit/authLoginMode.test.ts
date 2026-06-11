import assert from "node:assert/strict";
import test from "node:test";
import { resolveAuthLoginMode } from "../../lib/auth-login-mode";

test("resolveAuthLoginMode keeps local-only login as the default", () => {
    assert.deepEqual(
        resolveAuthLoginMode({
            oidcEnabled: false,
            localLoginEnabled: true,
        }),
        {
            showSsoButton: false,
            showLocalForm: true,
            showSeparator: false,
        }
    );
});

test("resolveAuthLoginMode shows SSO and separator when both modes are enabled", () => {
    assert.deepEqual(
        resolveAuthLoginMode({
            oidcEnabled: true,
            localLoginEnabled: true,
        }),
        {
            showSsoButton: true,
            showLocalForm: true,
            showSeparator: true,
        }
    );
});

test("resolveAuthLoginMode hides the local form when local login is disabled", () => {
    assert.deepEqual(
        resolveAuthLoginMode({
            oidcEnabled: true,
            localLoginEnabled: false,
        }),
        {
            showSsoButton: true,
            showLocalForm: false,
            showSeparator: false,
        }
    );
});
