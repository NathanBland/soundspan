const mockConfig = {
    oidc: {
        enabled: true,
        issuerUrl: "https://idp.example/realms/soundspan",
        clientId: "soundspan",
        clientSecret: "oidc-secret",
        redirectUri: "https://music.example/api/auth/oidc/callback",
        scopes: "openid profile email",
        autoProvision: false,
        adminGroup: "soundspan-admins",
        groupsClaim: "groups",
        emailClaim: "email",
        nameClaim: "name",
    },
};

jest.mock("../../config", () => ({
    config: mockConfig,
}));

const mockConfiguration = {
    serverMetadata: jest.fn(() => ({
        supportsPKCE: jest.fn(() => true),
    })),
};
const mockDiscovery = jest.fn(async () => mockConfiguration);
const mockRandomState = jest.fn(() => "state-1");
const mockRandomNonce = jest.fn(() => "nonce-1");
const mockRandomPKCECodeVerifier = jest.fn(() => "verifier-1");
const mockCalculatePKCECodeChallenge = jest.fn(async () => "challenge-1");
const mockBuildAuthorizationUrl = jest.fn(() => new URL("https://idp.example/auth"));
const mockAuthorizationCodeGrant = jest.fn(async () => ({
    id_token: "id-token",
    claims: () => ({
        sub: "subject-1",
        email: "alice@example.com",
        email_verified: true,
    }),
}));

const mockOpenIdClient = {
    discovery: (...args: Parameters<typeof mockDiscovery>) =>
        mockDiscovery(...args),
    randomState: (...args: Parameters<typeof mockRandomState>) =>
        mockRandomState(...args),
    randomNonce: (...args: Parameters<typeof mockRandomNonce>) =>
        mockRandomNonce(...args),
    randomPKCECodeVerifier: (
        ...args: Parameters<typeof mockRandomPKCECodeVerifier>
    ) => mockRandomPKCECodeVerifier(...args),
    calculatePKCECodeChallenge: (
        ...args: Parameters<typeof mockCalculatePKCECodeChallenge>
    ) => mockCalculatePKCECodeChallenge(...args),
    buildAuthorizationUrl: (...args: Parameters<typeof mockBuildAuthorizationUrl>) =>
        mockBuildAuthorizationUrl(...args),
    authorizationCodeGrant: (
        ...args: Parameters<typeof mockAuthorizationCodeGrant>
    ) => mockAuthorizationCodeGrant(...args),
};

import {
    __resetOpenIdClientForTests,
    __setOpenIdClientForTests,
    buildOidcAuthorizationUrl,
    exchangeOidcCallback,
    getOidcProviderId,
} from "../oidcAuth";

describe("oidcAuth service", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        __resetOpenIdClientForTests();
        __setOpenIdClientForTests(mockOpenIdClient as any);
        mockBuildAuthorizationUrl.mockReturnValue(
            new URL("https://idp.example/auth")
        );
    });

    it("builds authorization URL using discovery, PKCE, state, and nonce", async () => {
        const result = await buildOidcAuthorizationUrl();

        expect(mockDiscovery).toHaveBeenCalledWith(
            new URL("https://idp.example/realms/soundspan"),
            "soundspan",
            "oidc-secret"
        );
        expect(mockCalculatePKCECodeChallenge).toHaveBeenCalledWith("verifier-1");
        expect(mockBuildAuthorizationUrl).toHaveBeenCalledWith(
            mockConfiguration,
            {
                redirect_uri: "https://music.example/api/auth/oidc/callback",
                scope: "openid profile email",
                state: "state-1",
                nonce: "nonce-1",
                code_challenge: "challenge-1",
                code_challenge_method: "S256",
            }
        );
        expect(result).toEqual({
            redirectUrl: "https://idp.example/auth",
            state: "state-1",
            nonce: "nonce-1",
            codeVerifier: "verifier-1",
        });
    });

    it("exchanges callbacks with expected state, nonce, and PKCE verifier", async () => {
        const result = await exchangeOidcCallback(
            "https://music.example/api/auth/oidc/callback?state=state-1&code=abc",
            {
                state: "state-1",
                nonce: "nonce-1",
                codeVerifier: "verifier-1",
                returnTo: "/",
            }
        );

        expect(mockAuthorizationCodeGrant).toHaveBeenCalledWith(
            mockConfiguration,
            new URL("https://music.example/api/auth/oidc/callback?state=state-1&code=abc"),
            {
                expectedState: "state-1",
                expectedNonce: "nonce-1",
                pkceCodeVerifier: "verifier-1",
                idTokenExpected: true,
            },
            {
                redirect_uri: "https://music.example/api/auth/oidc/callback",
            }
        );
        expect(result).toEqual({
            idToken: "id-token",
            claims: {
                sub: "subject-1",
                email: "alice@example.com",
                email_verified: true,
            },
        });
    });

    it("uses issuer URL as the stable provider id", () => {
        expect(getOidcProviderId()).toBe(
            "oidc:https://idp.example/realms/soundspan"
        );
    });
});
