import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { api } from "../../lib/api";
import { consumeAuthRedirectTokensFromUrl } from "../../lib/auth-redirect";

type TestGlobalScope = {
    fetch?: unknown;
    window?: unknown;
    localStorage?: unknown;
};

const globalScope = globalThis as TestGlobalScope;
let previousFetch: unknown;
let previousWindow: unknown;
let previousLocalStorage: unknown;

function installStorage() {
    const values = new Map<string, string>();
    const storage = {
        getItem: (key: string) => values.get(key) ?? null,
        setItem: (key: string, value: string) => values.set(key, value),
        removeItem: (key: string) => values.delete(key),
    };

    globalScope.window = { localStorage: storage };
    globalScope.localStorage = storage;
    return values;
}

beforeEach(() => {
    previousFetch = globalScope.fetch;
    previousWindow = globalScope.window;
    previousLocalStorage = globalScope.localStorage;
});

afterEach(() => {
    api.clearToken();
    api.refreshBaseUrl();

    if (typeof previousFetch === "undefined") {
        delete globalScope.fetch;
    } else {
        globalScope.fetch = previousFetch;
    }

    if (typeof previousWindow === "undefined") {
        delete globalScope.window;
    } else {
        globalScope.window = previousWindow;
    }

    if (typeof previousLocalStorage === "undefined") {
        delete globalScope.localStorage;
    } else {
        globalScope.localStorage = previousLocalStorage;
    }
});

test("setToken stores access and refresh tokens for redirect handoff", () => {
    const values = installStorage();

    api.setToken("access-token", "refresh-token");

    assert.equal(api.getToken(), "access-token");
    assert.equal(values.get("auth_token"), "access-token");
    assert.equal(values.get("refresh_token"), "refresh-token");
});

test("redirect handoff consumes access and refresh tokens then cleans URL", () => {
    const values = installStorage();
    let replacedUrl = "";
    globalScope.window = {
        localStorage: globalScope.localStorage,
        location: {
            search: "?token=access-from-url&refreshToken=refresh-from-url",
            pathname: "/",
            hash: "",
        },
        history: {
            replaceState: (_state: unknown, _title: string, url: string) => {
                replacedUrl = url;
            },
        },
    };

    assert.equal(consumeAuthRedirectTokensFromUrl(), true);
    assert.equal(values.get("auth_token"), "access-from-url");
    assert.equal(values.get("refresh_token"), "refresh-from-url");
    assert.equal(replacedUrl, "/");
});

test("getAuthConfig reads OIDC and local-login flags from the API boundary", async () => {
    let requestedUrl = "";
    globalScope.fetch = async (url: string) => {
        requestedUrl = url;
        return new Response(
            JSON.stringify({
                oidcEnabled: true,
                localLoginEnabled: false,
            }),
            {
                status: 200,
                headers: { "Content-Type": "application/json" },
            }
        );
    };

    const result = await api.getAuthConfig();

    assert.equal(requestedUrl.endsWith("/api/auth/config"), true);
    assert.deepEqual(result, {
        oidcEnabled: true,
        localLoginEnabled: false,
    });
});
