import assert from "node:assert/strict";
import { mock, test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const Icon = () => React.createElement("i");

mock.module("lucide-react", {
    namedExports: {
        Copy: Icon,
        Eye: Icon,
        EyeOff: Icon,
        Info: Icon,
        Trash2: Icon,
    },
});

mock.module("@/lib/auth-context", {
    namedExports: {
        useAuth: () => ({
            user: {
                id: "u1",
                username: "alice",
                role: "user",
            },
        }),
    },
});

mock.module("@/lib/api", {
    namedExports: {
        api: {
            listAppPasswords: async () => ({ appPasswords: [] }),
            createAppPassword: async () => ({
                appPassword: {
                    id: "ap-1",
                    displayName: "Phone",
                    createdAt: "2026-01-01T00:00:00.000Z",
                    lastUsedAt: null,
                    revokedAt: null,
                    secret: "ssp_ap_secret",
                },
            }),
            revokeAppPassword: async () => ({ message: "App password revoked" }),
            getSubsonicPasswordStatus: async () => ({ hasPassword: false }),
            setSubsonicPassword: async () => ({ success: true }),
            clearSubsonicPassword: async () => ({ success: true }),
        },
    },
});

test("renders OpenSubsonic app-password controls with username", async () => {
    const { SubsonicRows } = await import(
        "../../features/settings/components/sections/SubsonicSection"
    );

    const html = renderToStaticMarkup(React.createElement(SubsonicRows));

    assert.match(html, /OpenSubsonic Access/);
    assert.match(html, /Use username alice/);
    assert.match(html, /Create App Password/);
    assert.match(html, /No app passwords yet/);
    assert.match(html, /legacy Subsonic password/);
});
