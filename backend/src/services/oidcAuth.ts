import { config } from "../config";

type OpenIdClientModule = typeof import("openid-client");
type OidcConfiguration = Awaited<ReturnType<OpenIdClientModule["discovery"]>>;

export interface OidcSessionState {
    state: string;
    nonce: string;
    codeVerifier: string;
    returnTo: string;
}

export interface OidcAuthorizationRequest {
    redirectUrl: string;
    state: string;
    nonce: string;
    codeVerifier: string;
}

export interface OidcCallbackResult {
    claims: Record<string, unknown>;
    idToken?: string;
}

const importOpenIdClient = new Function(
    "specifier",
    "return import(specifier)"
) as (specifier: string) => Promise<OpenIdClientModule>;

let oidcClientModule: OpenIdClientModule | null = null;
let oidcConfiguration: OidcConfiguration | null = null;

async function loadOpenIdClient(): Promise<OpenIdClientModule> {
    if (!oidcClientModule) {
        oidcClientModule = await importOpenIdClient("openid-client");
    }
    return oidcClientModule;
}

/** Injects a test double for the ESM-only openid-client module. */
export function __setOpenIdClientForTests(client: OpenIdClientModule): void {
    if (process.env.NODE_ENV !== "test") {
        throw new Error("OIDC client injection is only available in tests");
    }
    oidcClientModule = client;
    oidcConfiguration = null;
}

/** Clears cached discovery state between OIDC service tests. */
export function __resetOpenIdClientForTests(): void {
    if (process.env.NODE_ENV !== "test") {
        throw new Error("OIDC client reset is only available in tests");
    }
    oidcClientModule = null;
    oidcConfiguration = null;
}

async function getOidcConfiguration(): Promise<OidcConfiguration> {
    if (oidcConfiguration) {
        return oidcConfiguration;
    }

    if (!config.oidc.enabled) {
        throw new Error("OIDC is disabled");
    }

    const client = await loadOpenIdClient();
    oidcConfiguration = await client.discovery(
        new URL(config.oidc.issuerUrl),
        config.oidc.clientId,
        config.oidc.clientSecret
    );
    return oidcConfiguration;
}

/** Returns the stable provider id used for persisted external identities. */
export function getOidcProviderId(): string {
    return `oidc:${config.oidc.issuerUrl}`;
}

/** Builds the Authorization Code + PKCE redirect URL and generated checks. */
export async function buildOidcAuthorizationUrl(): Promise<OidcAuthorizationRequest> {
    const client = await loadOpenIdClient();
    const discoveredConfig = await getOidcConfiguration();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

    const redirectTo = client.buildAuthorizationUrl(discoveredConfig, {
        redirect_uri: config.oidc.redirectUri,
        scope: config.oidc.scopes,
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
    });

    return {
        redirectUrl: redirectTo.toString(),
        state,
        nonce,
        codeVerifier,
    };
}

/** Exchanges an OIDC callback URL for validated ID token claims. */
export async function exchangeOidcCallback(
    currentUrl: string,
    checks: OidcSessionState
): Promise<OidcCallbackResult> {
    const client = await loadOpenIdClient();
    const discoveredConfig = await getOidcConfiguration();

    const tokens = await client.authorizationCodeGrant(
        discoveredConfig,
        new URL(currentUrl),
        {
            expectedState: checks.state,
            expectedNonce: checks.nonce,
            pkceCodeVerifier: checks.codeVerifier,
            idTokenExpected: true,
        }
    );

    const helperClaims = (tokens as { claims?: () => unknown }).claims?.();
    const claims =
        helperClaims && typeof helperClaims === "object"
            ? (helperClaims as Record<string, unknown>)
            : parseJwtClaims(tokens.id_token);

    if (!claims || typeof claims.sub !== "string" || !claims.sub) {
        throw new Error("OIDC ID token did not include a subject");
    }

    return {
        claims,
        idToken: tokens.id_token,
    };
}

function parseJwtClaims(idToken?: string): Record<string, unknown> | null {
    if (!idToken) {
        return null;
    }

    const [, payload] = idToken.split(".");
    if (!payload) {
        return null;
    }

    try {
        return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    } catch {
        return null;
    }
}
