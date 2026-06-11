const mockConfig = {
    localLoginEnabled: true,
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

jest.mock("../../utils/logger", () => ({
    logger: {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    },
}));

const mockRequireAuth = jest.fn((_req: any, _res: any, next: () => void) => next());
const mockRequireAdmin = jest.fn((_req: any, _res: any, next: () => void) => next());
const mockGenerateToken = jest.fn(() => "jwt-access");
const mockGenerateRefreshToken = jest.fn(() => "jwt-refresh");

jest.mock("../../middleware/auth", () => ({
    requireAuth: mockRequireAuth,
    requireAdmin: mockRequireAdmin,
    generateToken: mockGenerateToken,
    generateRefreshToken: mockGenerateRefreshToken,
}));

const prisma = {
    user: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
    },
    userSettings: {
        create: jest.fn(),
    },
    externalIdentity: {
        findUnique: jest.fn(),
        create: jest.fn(),
    },
    $transaction: jest.fn(),
};

jest.mock("../../utils/db", () => ({
    prisma,
}));

const mockBuildOidcAuthorizationUrl = jest.fn();
const mockExchangeOidcCallback = jest.fn();
const mockGetOidcProviderId = jest.fn(
    () => "oidc:https://idp.example/realms/soundspan"
);

jest.mock("../../services/oidcAuth", () => ({
    buildOidcAuthorizationUrl: (...args: unknown[]) =>
        mockBuildOidcAuthorizationUrl(...args),
    exchangeOidcCallback: (...args: unknown[]) =>
        mockExchangeOidcCallback(...args),
    getOidcProviderId: () => mockGetOidcProviderId(),
}));

jest.mock("bcrypt", () => ({
    __esModule: true,
    default: {
        compare: jest.fn(),
        hash: jest.fn(),
    },
}));

jest.mock("speakeasy", () => ({
    __esModule: true,
    default: {
        totp: { verify: jest.fn() },
        generateSecret: jest.fn(),
    },
}));

jest.mock("qrcode", () => ({
    __esModule: true,
    default: {
        toDataURL: jest.fn(),
    },
}));

jest.mock("jsonwebtoken", () => ({
    __esModule: true,
    default: {
        verify: jest.fn(),
    },
}));

jest.mock("../../utils/encryption", () => ({
    encrypt: jest.fn((value: string) => `enc(${value})`),
    decrypt: jest.fn((value: string) => value),
}));

import router from "../auth";

function getHandler(path: string, method: "get" | "post" | "delete") {
    const layer = (router as any).stack.find(
        (entry: any) =>
            entry.route?.path === path && entry.route?.methods?.[method]
    );
    if (!layer) {
        throw new Error(`${method.toUpperCase()} route not found: ${path}`);
    }
    return layer.route.stack[layer.route.stack.length - 1].handle;
}

function createRes() {
    const res: any = {
        statusCode: 200,
        body: undefined as unknown,
        redirectUrl: undefined as string | undefined,
        status: jest.fn(function (code: number) {
            res.statusCode = code;
            return res;
        }),
        json: jest.fn(function (payload: unknown) {
            res.body = payload;
            return res;
        }),
        redirect: jest.fn(function (url: string) {
            res.redirectUrl = url;
            return res;
        }),
    };
    return res;
}

describe("OIDC auth routes", () => {
    const oidcLogin = getHandler("/oidc/login", "get");
    const oidcCallback = getHandler("/oidc/callback", "get");

    beforeEach(() => {
        jest.clearAllMocks();
        mockConfig.oidc.enabled = true;
        mockConfig.oidc.autoProvision = false;
        mockBuildOidcAuthorizationUrl.mockResolvedValue({
            redirectUrl: "https://idp.example/auth?state=state-1",
            state: "state-1",
            nonce: "nonce-1",
            codeVerifier: "verifier-1",
        });
        mockExchangeOidcCallback.mockResolvedValue({
            claims: {
                sub: "subject-1",
                email: "alice@example.com",
                email_verified: true,
                name: "Alice Example",
                groups: [],
            },
            idToken: "id-token",
        });
        prisma.externalIdentity.findUnique.mockResolvedValue(null);
        prisma.externalIdentity.create.mockResolvedValue({});
        prisma.user.findUnique.mockResolvedValue(null);
        prisma.user.create.mockResolvedValue({
            id: "u-new",
            username: "alice",
            displayName: "Alice Example",
            email: "alice@example.com",
            role: "user",
            tokenVersion: 0,
        });
        prisma.user.update.mockImplementation(async ({ data }: any) => ({
            id: "u-linked",
            username: "alice",
            role: data.role ?? "user",
            tokenVersion: 1,
        }));
        prisma.userSettings.create.mockResolvedValue({});
        prisma.$transaction.mockImplementation(async (fn: any) => fn(prisma));
    });

    it("builds an authorization URL and stores state, nonce, PKCE, and return path in session", async () => {
        const req = {
            query: { returnTo: "/settings" },
            session: {},
        } as any;
        const res = createRes();

        await oidcLogin(req, res);

        expect(mockBuildOidcAuthorizationUrl).toHaveBeenCalledWith();
        expect(req.session.oidc).toEqual({
            state: "state-1",
            nonce: "nonce-1",
            codeVerifier: "verifier-1",
            returnTo: "/settings",
        });
        expect(res.redirect).toHaveBeenCalledWith(
            "https://idp.example/auth?state=state-1"
        );
    });

    it("rejects callback when stored state is missing or mismatched", async () => {
        const req = {
            originalUrl: "/api/auth/oidc/callback?state=bad&code=abc",
            protocol: "https",
            get: jest.fn(() => "music.example"),
            query: { state: "bad", code: "abc" },
            session: {
                oidc: {
                    state: "state-1",
                    nonce: "nonce-1",
                    codeVerifier: "verifier-1",
                    returnTo: "/",
                },
            },
        } as any;
        const res = createRes();

        await oidcCallback(req, res);

        expect(res.statusCode).toBe(400);
        expect(res.body).toEqual({ error: "Invalid OIDC state" });
        expect(mockExchangeOidcCallback).not.toHaveBeenCalled();
    });

    it("logs in an existing user linked by provider subject", async () => {
        prisma.externalIdentity.findUnique.mockResolvedValueOnce({
            user: {
                id: "u-linked",
                username: "alice",
                role: "user",
                tokenVersion: 1,
            },
        });

        const req = buildCallbackReq();
        const res = createRes();

        await oidcCallback(req, res);

        expect(mockExchangeOidcCallback).toHaveBeenCalledWith(
            "https://music.example/api/auth/oidc/callback?state=state-1&code=abc",
            {
                state: "state-1",
                nonce: "nonce-1",
                codeVerifier: "verifier-1",
                returnTo: "/library",
            }
        );
        expect(req.session.userId).toBe("u-linked");
        expect(res.redirectUrl).toBe(
            "/library?token=jwt-access&refreshToken=jwt-refresh"
        );
    });

    it("auto-links by verified email only", async () => {
        prisma.user.findUnique.mockResolvedValueOnce({
            id: "u-email",
            username: "alice",
            role: "user",
            tokenVersion: 2,
        });

        const req = buildCallbackReq();
        const res = createRes();
        await oidcCallback(req, res);

        expect(prisma.user.findUnique).toHaveBeenCalledWith({
            where: { email: "alice@example.com" },
            select: {
                id: true,
                username: true,
                role: true,
                tokenVersion: true,
            },
        });
        expect(prisma.externalIdentity.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                userId: "u-email",
                providerSubject: "subject-1",
            }),
        });
        expect(res.redirectUrl).toContain("token=jwt-access");

        jest.clearAllMocks();
        mockExchangeOidcCallback.mockResolvedValueOnce({
            claims: {
                sub: "subject-2",
                email: "unverified@example.com",
                email_verified: false,
            },
        });
        const unverifiedReq = buildCallbackReq();
        const unverifiedRes = createRes();
        await oidcCallback(unverifiedReq, unverifiedRes);

        expect(prisma.user.findUnique).not.toHaveBeenCalledWith(
            expect.objectContaining({ where: { email: "unverified@example.com" } })
        );
        expect(unverifiedRes.redirectUrl).toBe(
            "/login?error=OIDC%20account%20is%20not%20linked"
        );
    });

    it("auto-provisions users and maps configured admin group", async () => {
        mockConfig.oidc.autoProvision = true;
        mockExchangeOidcCallback.mockResolvedValueOnce({
            claims: {
                sub: "subject-admin",
                email: "admin@example.com",
                email_verified: true,
                name: "Admin User",
                groups: ["soundspan-admins"],
            },
        });
        prisma.user.create.mockResolvedValueOnce({
            id: "u-admin",
            username: "admin",
            displayName: "Admin User",
            email: "admin@example.com",
            role: "admin",
            tokenVersion: 0,
        });

        const req = buildCallbackReq();
        const res = createRes();
        await oidcCallback(req, res);

        expect(prisma.user.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                username: "admin",
                email: "admin@example.com",
                displayName: "Admin User",
                passwordHash: null,
                role: "admin",
                onboardingComplete: true,
            }),
        });
        expect(prisma.userSettings.create).toHaveBeenCalledWith({
            data: expect.objectContaining({ userId: "u-admin" }),
        });
        expect(prisma.externalIdentity.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                userId: "u-admin",
                providerSubject: "subject-admin",
            }),
        });
        expect(res.redirectUrl).toContain("token=jwt-access");
    });

    it("does not persist unverified email claims when auto-provisioning", async () => {
        mockConfig.oidc.autoProvision = true;
        mockExchangeOidcCallback.mockResolvedValueOnce({
            claims: {
                sub: "subject-unverified",
                preferred_username: "charlie",
                email: "charlie@example.com",
                email_verified: false,
                name: "Charlie User",
                groups: [],
            },
        });
        prisma.user.create.mockResolvedValueOnce({
            id: "u-charlie",
            username: "charlie",
            displayName: "Charlie User",
            email: null,
            role: "user",
            tokenVersion: 0,
        });

        const req = buildCallbackReq();
        const res = createRes();
        await oidcCallback(req, res);

        expect(prisma.user.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                username: "charlie",
                email: null,
                displayName: "Charlie User",
                passwordHash: null,
                role: "user",
                onboardingComplete: true,
            }),
        });
        expect(prisma.externalIdentity.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                userId: "u-charlie",
                providerSubject: "subject-unverified",
                email: null,
            }),
        });
        expect(res.redirectUrl).toContain("token=jwt-access");
    });
});

function buildCallbackReq() {
    return {
        originalUrl: "/api/auth/oidc/callback?state=state-1&code=abc",
        protocol: "https",
        get: jest.fn(() => "music.example"),
        query: { state: "state-1", code: "abc" },
        session: {
            oidc: {
                state: "state-1",
                nonce: "nonce-1",
                codeVerifier: "verifier-1",
                returnTo: "/library",
            },
        },
    } as any;
}
