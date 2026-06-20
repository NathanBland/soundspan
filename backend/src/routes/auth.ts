import { Request, Response, Router } from "express";
import { logger } from "../utils/logger";
import bcrypt from "bcrypt";
import { prisma } from "../utils/db";
import { z } from "zod";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";
import type { Prisma } from "@prisma/client";
import {
    requireAuth,
    requireAdmin,
    generateToken,
    generateRefreshToken,
    verifyAuthToken,
} from "../middleware/auth";
import { encrypt, decrypt } from "../utils/encryption";
import { APP_PASSWORD_SECRET_PREFIX } from "../utils/appPasswords";
import { BRAND_NAME } from "../config/brand";
import { timingSafeCompare } from "../utils/timingSafe";
import { runDummyBcrypt } from "../utils/dummyCredential";
import { config } from "../config";
import {
    buildOidcAuthorizationUrl,
    exchangeOidcCallback,
    getOidcProviderId,
    OidcSessionState,
} from "../services/oidcAuth";

const router = Router();

const loginSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1),
});

const inviteCodeSchema = z.object({
    ttl: z.enum(["1h", "6h", "24h", "7d", "30d", "never"]),
    maxUses: z.number().int().min(1).max(100).default(1),
});

const registerSchema = z.object({
    inviteCode: z.string().min(1),
    username: z
        .string()
        .min(3)
        .max(32)
        .regex(/^[a-zA-Z0-9_]+$/, "Username must be alphanumeric (underscores allowed)"),
    displayName: z.string().min(1).max(64),
    password: z.string().min(6).max(128),
    confirmPassword: z.string(),
    email: z.string().email(),
}).refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
});

// Unambiguous character set for invite codes (no 0/O/1/I/L)
const INVITE_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateInviteCode(): string {
    const bytes = crypto.randomBytes(8);
    let code = "";
    for (let i = 0; i < 8; i++) {
        code += INVITE_CODE_CHARS[bytes[i] % INVITE_CODE_CHARS.length];
    }
    return code;
}

function ttlToExpiresAt(ttl: string): Date | null {
    const now = Date.now();
    switch (ttl) {
        case "1h":
            return new Date(now + 60 * 60 * 1000);
        case "6h":
            return new Date(now + 6 * 60 * 60 * 1000);
        case "24h":
            return new Date(now + 24 * 60 * 60 * 1000);
        case "7d":
            return new Date(now + 7 * 24 * 60 * 60 * 1000);
        case "30d":
            return new Date(now + 30 * 24 * 60 * 60 * 1000);
        case "never":
            return null;
        default:
            return new Date(now + 24 * 60 * 60 * 1000);
    }
}

const subsonicPasswordSchema = z.object({
    password: z.string().min(8).max(128),
});

const appPasswordSchema = z.object({
    displayName: z.string().trim().min(1).max(64),
});

type LoginUser = {
    id: string;
    username: string;
    role: string;
    tokenVersion: number;
};

// Use shared encryption module for 2FA secrets
const encrypt2FASecret = encrypt;
const decrypt2FASecret = decrypt;

function generateAppPasswordSecret(): string {
    return `${APP_PASSWORD_SECRET_PREFIX}${crypto.randomBytes(32).toString("base64url")}`;
}

function normalizeReturnTo(value: unknown): string {
    if (typeof value !== "string") {
        return "/";
    }

    const trimmed = value.trim();
    if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
        return "/";
    }
    return trimmed;
}

function buildAbsoluteRequestUrl(req: Request): string {
    return `${req.protocol}://${req.get("host")}${req.originalUrl}`;
}

function redirectWithTokens(res: Response, returnTo: string, user: LoginUser) {
    const token = generateToken(user);
    const refreshToken = generateRefreshToken({
        id: user.id,
        tokenVersion: user.tokenVersion,
    });
    const separator = returnTo.includes("?") ? "&" : "?";
    const params = new URLSearchParams({ token, refreshToken });
    return res.redirect(`${returnTo}${separator}${params.toString()}`);
}

function redirectLoginError(res: Response, message: string) {
    return res.redirect(`/login?error=${encodeURIComponent(message)}`);
}

function getClaimString(
    claims: Record<string, unknown>,
    claimName: string
): string | null {
    const value = claimName
        .split(".")
        .reduce<unknown>((current, key) => {
            if (!current || typeof current !== "object") {
                return undefined;
            }
            return (current as Record<string, unknown>)[key];
        }, claims);

    return typeof value === "string" && value.trim() ? value.trim() : null;
}

function getClaimStrings(
    claims: Record<string, unknown>,
    claimName: string
): string[] {
    const value = claimName
        .split(".")
        .reduce<unknown>((current, key) => {
            if (!current || typeof current !== "object") {
                return undefined;
            }
            return (current as Record<string, unknown>)[key];
        }, claims);

    if (Array.isArray(value)) {
        return value.filter((entry): entry is string => typeof entry === "string");
    }

    if (typeof value === "string" && value.trim()) {
        return [value.trim()];
    }

    return [];
}

function isOidcAdmin(claims: Record<string, unknown>): boolean {
    if (!config.oidc.adminGroup) {
        return false;
    }
    return getClaimStrings(claims, config.oidc.groupsClaim).includes(
        config.oidc.adminGroup
    );
}

function usernameCandidateFromClaims(
    claims: Record<string, unknown>,
    subject: string,
    email: string | null,
    displayName: string | null
): string {
    const base =
        email?.split("@")[0] ||
        getClaimString(claims, "preferred_username") ||
        displayName ||
        subject;
    const normalized = base
        .toLowerCase()
        .replace(/[^a-z0-9_]+/g, "_")
        .replace(/^_+|_+$/g, "")
        .slice(0, 28);
    return normalized.length >= 3 ? normalized : `oidc_${normalized || "user"}`;
}

async function resolveAvailableUsername(
    tx: Prisma.TransactionClient,
    claims: Record<string, unknown>,
    subject: string,
    email: string | null,
    displayName: string | null
): Promise<string> {
    const base = usernameCandidateFromClaims(claims, subject, email, displayName);
    for (let index = 0; index < 100; index++) {
        const candidate =
            index === 0 ? base : `${base.slice(0, 26)}_${index}`;
        const existing = await tx.user.findUnique({
            where: { username: candidate },
            select: { id: true },
        });
        if (!existing) {
            return candidate;
        }
    }
    return `oidc_${crypto.randomBytes(6).toString("hex")}`;
}

async function createDefaultUserSettings(
    tx: Prisma.TransactionClient,
    userId: string
) {
    await tx.userSettings.create({
        data: {
            userId,
            playbackQuality: "original",
            wifiOnly: false,
            offlineEnabled: false,
            maxCacheSizeMb: 10240,
        },
    });
}

async function resolveOidcUser(
    claims: Record<string, unknown>
): Promise<LoginUser | null> {
    const subject = getClaimString(claims, "sub");
    if (!subject) {
        throw new Error("OIDC subject is missing");
    }

    const provider = getOidcProviderId();
    const claimedEmail = getClaimString(claims, config.oidc.emailClaim);
    const verifiedEmail = claims.email_verified === true ? claimedEmail : null;
    const displayName = getClaimString(claims, config.oidc.nameClaim);
    const admin = isOidcAdmin(claims);

    const linked = await prisma.externalIdentity.findUnique({
        where: {
            provider_providerSubject: {
                provider,
                providerSubject: subject,
            },
        },
        include: {
            user: {
                select: {
                    id: true,
                    username: true,
                    role: true,
                    tokenVersion: true,
                },
            },
        },
    });

    if (linked?.user) {
        if (admin && linked.user.role !== "admin") {
            return prisma.user.update({
                where: { id: linked.user.id },
                data: { role: "admin" },
                select: {
                    id: true,
                    username: true,
                    role: true,
                    tokenVersion: true,
                },
            });
        }
        return linked.user;
    }

    if (verifiedEmail) {
        const emailUser = await prisma.user.findUnique({
            where: { email: verifiedEmail },
            select: {
                id: true,
                username: true,
                role: true,
                tokenVersion: true,
            },
        });

        if (emailUser) {
            await prisma.externalIdentity.create({
                data: {
                    userId: emailUser.id,
                    provider,
                    providerSubject: subject,
                    email: verifiedEmail,
                    displayName,
                },
            });

            if (admin && emailUser.role !== "admin") {
                return prisma.user.update({
                    where: { id: emailUser.id },
                    data: { role: "admin" },
                    select: {
                        id: true,
                        username: true,
                        role: true,
                        tokenVersion: true,
                    },
                });
            }
            return emailUser;
        }
    }

    if (!config.oidc.autoProvision) {
        return null;
    }

    return prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        const username = await resolveAvailableUsername(
            tx,
            claims,
            subject,
            verifiedEmail,
            displayName
        );
        const user = await tx.user.create({
            data: {
                username,
                displayName,
                email: verifiedEmail,
                passwordHash: null,
                role: admin ? "admin" : "user",
                onboardingComplete: true,
            },
        });

        await createDefaultUserSettings(tx, user.id);
        await tx.externalIdentity.create({
            data: {
                userId: user.id,
                provider,
                providerSubject: subject,
                email: verifiedEmail,
                displayName,
            },
        });

        return {
            id: user.id,
            username: user.username,
            role: user.role,
            tokenVersion: user.tokenVersion,
        };
    });
}

/**
 * @openapi
 * /auth/config:
 *   get:
 *     summary: Get public auth feature flags
 *     description: Returns login-mode flags used by the web login UI.
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Auth feature flags
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 oidcEnabled:
 *                   type: boolean
 *                 localLoginEnabled:
 *                   type: boolean
 */
router.get("/config", (_req, res) => {
    res.json({
        oidcEnabled: config.oidc.enabled,
        localLoginEnabled: config.localLoginEnabled,
    });
});

/**
 * @openapi
 * /auth/oidc/login:
 *   get:
 *     summary: Start OIDC login
 *     description: Starts the OIDC Authorization Code flow with PKCE and redirects to the identity provider.
 *     tags: [Authentication]
 *     parameters:
 *       - in: query
 *         name: returnTo
 *         schema:
 *           type: string
 *         description: Same-origin path to return to after login.
 *     responses:
 *       302:
 *         description: Redirects to the OIDC provider authorization URL
 *       404:
 *         description: OIDC is not enabled
 */
router.get("/oidc/login", async (req, res) => {
    if (!config.oidc.enabled) {
        return res.status(404).json({ error: "OIDC is not enabled" });
    }

    try {
        const authorization = await buildOidcAuthorizationUrl();
        req.session.oidc = {
            state: authorization.state,
            nonce: authorization.nonce,
            codeVerifier: authorization.codeVerifier,
            returnTo: normalizeReturnTo(req.query.returnTo),
        };
        return res.redirect(authorization.redirectUrl);
    } catch (error) {
        logger.error("OIDC login start error:", error);
        return redirectLoginError(res, "OIDC login failed");
    }
});

/**
 * @openapi
 * /auth/oidc/callback:
 *   get:
 *     summary: Complete OIDC login
 *     description: Validates the OIDC callback, links or provisions the user, and redirects with web tokens.
 *     tags: [Authentication]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: state
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Redirects to the web app with access and refresh tokens or a login error
 *       400:
 *         description: Invalid OIDC state
 *       404:
 *         description: OIDC is not enabled
 */
router.get("/oidc/callback", async (req, res) => {
    if (!config.oidc.enabled) {
        return res.status(404).json({ error: "OIDC is not enabled" });
    }

    const stored = req.session.oidc;
    const state = typeof req.query.state === "string" ? req.query.state : "";
    if (!stored || !state || state !== stored.state) {
        delete req.session.oidc;
        return res.status(400).json({ error: "Invalid OIDC state" });
    }

    const checks: OidcSessionState = { ...stored };
    delete req.session.oidc;

    const callbackUrl = `${config.oidc.redirectUri}${req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?")) : ""}`;
    try {
        const result = await exchangeOidcCallback(callbackUrl, checks);
        const user = await resolveOidcUser(result.claims);
        if (!user) {
            return redirectLoginError(res, "OIDC account is not linked");
        }

        req.session.userId = user.id;
        return redirectWithTokens(res, checks.returnTo, user);
    } catch (error) {
        const cause =
            error instanceof Error &&
            (error as Error & { cause?: unknown }).cause != null
                ? (error as Error & { cause?: unknown }).cause
                : undefined;
        logger.error("OIDC callback error", {
            message: error instanceof Error ? error.message : String(error),
            cause,
            callbackUrl,
        });
        return redirectLoginError(res, "OIDC login failed");
    }
});

/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Login with username and password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// POST /auth/login
router.post("/login", async (req, res) => {
    try {
        if (!config.localLoginEnabled) {
            return res.status(403).json({ error: "Local login is disabled" });
        }

        logger.debug(`[AUTH] Login attempt for user: ${req.body?.username}`);
        const { username, password } = loginSchema.parse(req.body);
        const { token } = req.body; // 2FA token if provided

        // Look up by username first, then by email
        const user =
            (await prisma.user.findUnique({ where: { username } })) ??
            (await prisma.user.findUnique({ where: { email: username } }));
        if (!user) {
            // Run dummy bcrypt to equalize response timing with the valid-user
            // path, preventing username enumeration via timing side-channel.
            await runDummyBcrypt();
            logger.debug(`[AUTH] User not found: ${username}`);
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (!user.passwordHash) {
            await runDummyBcrypt();
            logger.debug(`[AUTH] User has no local password: ${username}`);
            return res.status(401).json({ error: "Invalid credentials" });
        }

        logger.debug(`[AUTH] Verifying password for user: ${username}`);
        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) {
            logger.debug(`[AUTH] Invalid password for user: ${username}`);
            return res.status(401).json({ error: "Invalid credentials" });
        }
        logger.debug(`[AUTH] Password verified for user: ${username}`);

        // Check if 2FA is enabled
        if (user.twoFactorEnabled && user.twoFactorSecret) {
            if (!token) {
                return res.status(200).json({
                    requires2FA: true,
                    message: "2FA token required",
                });
            }

            // Check if it's a recovery code
            const isRecoveryCode = /^[A-F0-9]{8}$/i.test(token);

            if (isRecoveryCode && user.twoFactorRecoveryCodes) {
                const encryptedCodes = user.twoFactorRecoveryCodes;
                const decryptedCodes = decrypt2FASecret(encryptedCodes);
                const hashedCodes = decryptedCodes.split(",");

                const providedHash = crypto
                    .createHash("sha256")
                    .update(token.toUpperCase())
                    .digest("hex");

                // Iterate all codes with constant-time comparison to avoid
                // timing leaks that reveal which code position matched.
                let codeIndex = -1;
                for (let i = 0; i < hashedCodes.length; i++) {
                    if (timingSafeCompare(hashedCodes[i], providedHash)) {
                        codeIndex = i;
                    }
                }
                if (codeIndex === -1) {
                    return res
                        .status(401)
                        .json({ error: "Invalid recovery code" });
                }

                hashedCodes.splice(codeIndex, 1);
                await prisma.user.update({
                    where: { id: user.id },
                    data: {
                        twoFactorRecoveryCodes: encrypt2FASecret(
                            hashedCodes.join(",")
                        ),
                    },
                });
            } else {
                // Verify TOTP token
                const secret = decrypt2FASecret(user.twoFactorSecret);
                const verified = speakeasy.totp.verify({
                    secret,
                    encoding: "base32",
                    token,
                    window: 2,
                });

                if (!verified) {
                    return res.status(401).json({ error: "Invalid 2FA token" });
                }
            }
        }

        // Generate JWT tokens
        const jwtToken = generateToken({
            id: user.id,
            username: user.username,
            role: user.role,
            tokenVersion: user.tokenVersion,
        });
        const refreshToken = generateRefreshToken({
            id: user.id,
            tokenVersion: user.tokenVersion,
        });

        res.json({
            token: jwtToken,
            refreshToken: refreshToken,
            user: {
                id: user.id,
                username: user.username,
                displayName: user.displayName,
                role: user.role,
            },
        });
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res
                .status(400)
                .json({ error: "Invalid request", details: err.errors });
        }
        logger.error("Login error:", err);
        res.status(500).json({ error: "Internal error" });
    }
});

/**
 * @openapi
 * /api/auth/logout:
 *   post:
 *     summary: Logout the current user
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
// POST /auth/logout - JWT is stateless, logout is handled client-side
router.post("/logout", (req, res) => {
    // With JWT, logout is handled by client removing the token
    // No server-side session to destroy
    res.json({ message: "Logged out" });
});

/**
 * @openapi
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token using a refresh token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: New access and refresh tokens
 *       400:
 *         description: Refresh token required
 *       401:
 *         description: Invalid or expired refresh token
 */
// POST /auth/refresh - Refresh access token using refresh token
router.post("/refresh", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: "Refresh token required" });
    }

    try {
        // Verify through the shared helper: it pins the HS256 algorithm and
        // resolves the secret from one validated source (no inline process.env
        // read, no `as any`).
        const decoded = verifyAuthToken(refreshToken);

        if (decoded.type !== "refresh") {
            return res.status(401).json({ error: "Invalid refresh token" });
        }

        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: {
                id: true,
                username: true,
                role: true,
                tokenVersion: true,
            },
        });

        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        // Validate tokenVersion
        if (decoded.tokenVersion !== user.tokenVersion) {
            return res.status(401).json({ error: "Token invalidated" });
        }

        const newAccessToken = generateToken(user);
        const newRefreshToken = generateRefreshToken(user);

        return res.json({
            token: newAccessToken,
            refreshToken: newRefreshToken,
        });
    } catch (error) {
        return res.status(401).json({ error: "Invalid refresh token" });
    }
});

/**
 * @openapi
 * /auth/me:
 *   get:
 *     summary: Get current authenticated user
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Current user information
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// GET /auth/me
router.get("/me", requireAuth, async (req, res) => {
    const user = await prisma.user.findUnique({
        where: { id: req.user!.id },
        select: {
            id: true,
            username: true,
            displayName: true,
            email: true,
            role: true,
            onboardingComplete: true,
            enrichmentSettings: true,
            createdAt: true,
        },
    });

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
});

/**
 * @openapi
 * /api/auth/change-password:
 *   post:
 *     summary: Change the current user's password
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *               newPassword:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Current password is incorrect
 *       404:
 *         description: User not found
 */
// POST /auth/change-password
router.post("/change-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res
                .status(400)
                .json({ error: "Current and new password are required" });
        }

        if (newPassword.length < 6) {
            return res
                .status(400)
                .json({ error: "New password must be at least 6 characters" });
        }

        // Verify current password
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (!user.passwordHash) {
            await runDummyBcrypt();
            return res
                .status(401)
                .json({ error: "Current password is incorrect" });
        }

        const valid = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!valid) {
            return res
                .status(401)
                .json({ error: "Current password is incorrect" });
        }

        // Update password and increment tokenVersion to invalidate all existing tokens
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                passwordHash: newPasswordHash,
                tokenVersion: { increment: 1 },
            },
        });

        res.json({ message: "Password changed successfully" });
    } catch (error) {
        logger.error("Change password error:", error);
        res.status(500).json({ error: "Failed to change password" });
    }
});

/**
 * @openapi
 * /api/auth/change-email:
 *   post:
 *     summary: Change the current user's email address
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Email updated successfully
 *       400:
 *         description: Invalid email or email already in use
 *       401:
 *         description: Not authenticated
 */
// POST /auth/change-email
router.post("/change-email", requireAuth, async (req, res) => {
    try {
        const schema = z.object({ email: z.string().email() });
        const { email } = schema.parse(req.body);

        // Check uniqueness
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing && existing.id !== req.user!.id) {
            return res.status(400).json({ error: "Email already in use" });
        }

        await prisma.user.update({
            where: { id: req.user!.id },
            data: { email },
        });

        res.json({ message: "Email updated", email });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid email address" });
        }
        logger.error("Change email error:", error);
        res.status(500).json({ error: "Failed to change email" });
    }
});

/**
 * @openapi
 * /api/auth/users:
 *   get:
 *     summary: List all users (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: List of all users
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 */
// GET /auth/users (Admin only)
router.get("/users", requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                username: true,
                email: true,
                role: true,
                onboardingComplete: true,
                createdAt: true,
            },
            orderBy: { createdAt: "asc" },
        });

        res.json(users);
    } catch (error) {
        logger.error("Get users error:", error);
        res.status(500).json({ error: "Failed to get users" });
    }
});

/**
 * @openapi
 * /api/auth/create-user:
 *   post:
 *     summary: Create a new user account (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *                 format: password
 *               role:
 *                 type: string
 *                 enum: [user, admin]
 *     responses:
 *       200:
 *         description: User created successfully
 *       400:
 *         description: Invalid request or username already taken
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 */
// POST /auth/create-user (Admin only)
router.post("/create-user", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password are required" });
        }

        if (password.length < 6) {
            return res
                .status(400)
                .json({ error: "Password must be at least 6 characters" });
        }

        if (role && !["user", "admin"].includes(role)) {
            return res.status(400).json({ error: "Invalid role" });
        }

        // Check if username exists
        const existing = await prisma.user.findUnique({
            where: { username },
        });

        if (existing) {
            return res.status(400).json({ error: "Username already taken" });
        }

        // Create user
        const passwordHash = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                username,
                passwordHash,
                role: role || "user",
                onboardingComplete: true, // Skip onboarding for created users
            },
        });

        // Create default user settings
        await prisma.userSettings.create({
            data: {
                userId: user.id,
                playbackQuality: "original",
                wifiOnly: false,
                offlineEnabled: false,
                maxCacheSizeMb: 10240,
            },
        });

        res.json({
            id: user.id,
            username: user.username,
            role: user.role,
            createdAt: user.createdAt,
        });
    } catch (error) {
        logger.error("Create user error:", error);
        res.status(500).json({ error: "Failed to create user" });
    }
});

/**
 * @openapi
 * /api/auth/users/{id}:
 *   patch:
 *     summary: Update a user's username, email, or password (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: The user ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: User updated successfully
 *       400:
 *         description: Invalid request or no fields to update
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
// PATCH /auth/users/:id (Admin only) - Edit user's username, email, or password
router.patch("/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateSchema = z.object({
            username: z
                .string()
                .min(3)
                .max(32)
                .regex(/^[a-zA-Z0-9_]+$/, "Username must be alphanumeric (underscores allowed)")
                .optional(),
            email: z.string().email().optional().nullable(),
            password: z.string().min(6).max(128).optional(),
        });

        const data = updateSchema.parse(req.body);

        // Check the target user exists
        const targetUser = await prisma.user.findUnique({ where: { id } });
        if (!targetUser) {
            return res.status(404).json({ error: "User not found" });
        }

        // Check username uniqueness if changing
        if (data.username && data.username !== targetUser.username) {
            const existing = await prisma.user.findUnique({
                where: { username: data.username },
            });
            if (existing) {
                return res.status(400).json({ error: "Username already taken" });
            }
        }

        // Check email uniqueness if changing
        if (data.email && data.email !== targetUser.email) {
            const existing = await prisma.user.findUnique({
                where: { email: data.email },
            });
            if (existing) {
                return res.status(400).json({ error: "Email already in use" });
            }
        }

        // Build update payload
        const updateData: Record<string, unknown> = {};
        if (data.username) updateData.username = data.username;
        if (data.email !== undefined) updateData.email = data.email;
        if (data.password) {
            updateData.passwordHash = await bcrypt.hash(data.password, 10);
            updateData.tokenVersion = { increment: 1 };
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No fields to update" });
        }

        const updated = await prisma.user.update({
            where: { id },
            data: updateData,
            select: {
                id: true,
                username: true,
                email: true,
                role: true,
                createdAt: true,
            },
        });

        res.json(updated);
    } catch (err) {
        if (err instanceof z.ZodError) {
            const firstError = err.errors[0];
            return res.status(400).json({
                error: firstError.message,
                details: err.errors,
            });
        }
        logger.error("Update user error:", err);
        res.status(500).json({ error: "Failed to update user" });
    }
});

/**
 * @openapi
 * /api/auth/users/{id}:
 *   delete:
 *     summary: Delete a user account (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: The user ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Cannot delete your own account
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
// DELETE /auth/users/:id (Admin only)
router.delete("/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent deleting yourself
        if (id === req.user!.id) {
            return res
                .status(400)
                .json({ error: "Cannot delete your own account" });
        }

        // Delete user (cascade will handle related data)
        await prisma.user.delete({
            where: { id },
        });

        res.json({ message: "User deleted successfully" });
    } catch (error: any) {
        logger.error("Delete user error:", error);
        if (error.code === "P2025") {
            return res.status(404).json({ error: "User not found" });
        }
        res.status(500).json({ error: "Failed to delete user" });
    }
});

/**
 * @openapi
 * /api/auth/invite-codes:
 *   post:
 *     summary: Generate a new invite code (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - ttl
 *             properties:
 *               ttl:
 *                 type: string
 *                 enum: [1h, 6h, 24h, 7d, 30d, never]
 *               maxUses:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 100
 *                 default: 1
 *     responses:
 *       200:
 *         description: Invite code created successfully
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 */
// POST /auth/invite-codes - Generate a new invite code (admin only)
router.post(
    "/invite-codes",
    requireAuth,
    requireAdmin,
    async (req, res) => {
        try {
            const { ttl, maxUses } = inviteCodeSchema.parse(req.body);
            const expiresAt = ttlToExpiresAt(ttl);

            // Retry loop for uniqueness
            let code: string;
            let attempts = 0;
            do {
                code = generateInviteCode();
                const existing = await prisma.inviteCode.findUnique({
                    where: { code },
                });
                if (!existing) break;
                attempts++;
            } while (attempts < 10);

            if (attempts >= 10) {
                return res
                    .status(500)
                    .json({ error: "Failed to generate unique code" });
            }

            const inviteCode = await prisma.inviteCode.create({
                data: {
                    code,
                    createdBy: req.user!.id,
                    expiresAt,
                    maxUses,
                },
            });

            res.json({
                id: inviteCode.id,
                code: inviteCode.code,
                expiresAt: inviteCode.expiresAt,
                maxUses: inviteCode.maxUses,
                createdAt: inviteCode.createdAt,
            });
        } catch (err) {
            if (err instanceof z.ZodError) {
                return res
                    .status(400)
                    .json({ error: "Invalid request", details: err.errors });
            }
            logger.error("Create invite code error:", err);
            res.status(500).json({ error: "Failed to create invite code" });
        }
    }
);

/**
 * @openapi
 * /api/auth/invite-codes:
 *   get:
 *     summary: List all invite codes (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: List of all invite codes with status
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 */
// GET /auth/invite-codes - List all invite codes (admin only)
router.get(
    "/invite-codes",
    requireAuth,
    requireAdmin,
    async (_req, res) => {
        try {
            const codes = await prisma.inviteCode.findMany({
                orderBy: { createdAt: "desc" },
                include: {
                    creator: {
                        select: { username: true },
                    },
                },
            });

            const now = new Date();
            const codesWithStatus = codes.map((c: {
                id: string;
                code: string;
                maxUses: number;
                useCount: number;
                expiresAt: Date | null;
                createdAt: Date;
                revoked: boolean;
                creator: { username: string };
            }) => {
                let status: string;
                if (c.revoked) {
                    status = "revoked";
                } else if (c.useCount >= c.maxUses) {
                    status = "exhausted";
                } else if (c.expiresAt && c.expiresAt < now) {
                    status = "expired";
                } else {
                    status = "active";
                }
                return {
                    id: c.id,
                    code: c.code,
                    status,
                    maxUses: c.maxUses,
                    useCount: c.useCount,
                    expiresAt: c.expiresAt,
                    createdAt: c.createdAt,
                    createdBy: c.creator.username,
                };
            });

            res.json(codesWithStatus);
        } catch (err) {
            logger.error("List invite codes error:", err);
            res.status(500).json({ error: "Failed to list invite codes" });
        }
    }
);

/**
 * @openapi
 * /api/auth/invite-codes/{id}:
 *   delete:
 *     summary: Revoke an invite code (admin only)
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: The invite code ID
 *     responses:
 *       200:
 *         description: Invite code revoked successfully
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Invite code not found
 */
// DELETE /auth/invite-codes/:id - Revoke an invite code (admin only)
router.delete(
    "/invite-codes/:id",
    requireAuth,
    requireAdmin,
    async (req, res) => {
        try {
            await prisma.inviteCode.update({
                where: { id: req.params.id },
                data: { revoked: true },
            });
            res.json({ message: "Invite code revoked" });
        } catch (err: any) {
            if (err.code === "P2025") {
                return res.status(404).json({ error: "Invite code not found" });
            }
            logger.error("Revoke invite code error:", err);
            res.status(500).json({ error: "Failed to revoke invite code" });
        }
    }
);

/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     summary: Register a new user account with an invite code
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - inviteCode
 *               - username
 *               - displayName
 *               - password
 *               - confirmPassword
 *               - email
 *             properties:
 *               inviteCode:
 *                 type: string
 *               username:
 *                 type: string
 *               displayName:
 *                 type: string
 *               password:
 *                 type: string
 *                 format: password
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Registration successful, returns JWT tokens
 *       400:
 *         description: Invalid request, invite code, or username/email already taken
 */
// Thrown inside the registration transaction when the invite code has no
// remaining uses at consume time, so the whole transaction rolls back (no user
// is created) and the handler can return a clean 400.
class InviteCodeExhaustedError extends Error {}

// POST /auth/register - Public registration with invite code
router.post("/register", async (req, res) => {
    try {
        const data = registerSchema.parse(req.body);

        // Validate invite code
        const invite = await prisma.inviteCode.findUnique({
            where: { code: data.inviteCode.toUpperCase() },
        });

        if (!invite) {
            return res.status(400).json({ error: "Invalid invite code" });
        }
        if (invite.revoked) {
            return res.status(400).json({ error: "This invite code has been revoked" });
        }
        if (invite.useCount >= invite.maxUses) {
            return res.status(400).json({ error: "This invite code has been fully used" });
        }
        if (invite.expiresAt && invite.expiresAt < new Date()) {
            return res.status(400).json({ error: "This invite code has expired" });
        }

        // Check username uniqueness
        const existingUser = await prisma.user.findUnique({
            where: { username: data.username },
        });
        if (existingUser) {
            return res.status(400).json({ error: "Username already taken" });
        }

        // Check email uniqueness
        const existingEmail = await prisma.user.findFirst({
            where: { email: data.email },
        });
        if (existingEmail) {
            return res.status(400).json({ error: "Email already in use" });
        }

        // Create user, settings, and usage record in a transaction
        const passwordHash = await bcrypt.hash(data.password, 10);

        const result = await prisma.$transaction(async (tx) => {
            // Atomically consume one use of the invite code — only if uses remain
            // and it isn't revoked. This closes the TOCTOU between the useCount
            // check above (read before the transaction) and the increment below:
            // two concurrent registrations on a single-use code can no longer
            // both pass. If nothing was consumed, abort so no user is created.
            const consumed = await tx.inviteCode.updateMany({
                where: {
                    id: invite.id,
                    revoked: false,
                    useCount: { lt: invite.maxUses },
                },
                data: { useCount: { increment: 1 } },
            });
            if (consumed.count === 0) {
                throw new InviteCodeExhaustedError();
            }

            const user = await tx.user.create({
                data: {
                    username: data.username,
                    displayName: data.displayName,
                    email: data.email,
                    passwordHash,
                    role: "user",
                    onboardingComplete: true,
                },
            });

            await tx.userSettings.create({
                data: {
                    userId: user.id,
                    playbackQuality: "original",
                    wifiOnly: false,
                    offlineEnabled: false,
                    maxCacheSizeMb: 10240,
                },
            });

            await tx.inviteCodeUsage.create({
                data: {
                    inviteCodeId: invite.id,
                    usedBy: user.id,
                },
            });

            return user;
        });

        // Generate JWT tokens
        const jwtToken = generateToken({
            id: result.id,
            username: result.username,
            role: result.role,
            tokenVersion: result.tokenVersion,
        });
        const refreshToken = generateRefreshToken({
            id: result.id,
            tokenVersion: result.tokenVersion,
        });

        res.json({
            token: jwtToken,
            refreshToken,
            user: {
                id: result.id,
                username: result.username,
                displayName: result.displayName,
                role: result.role,
            },
        });
    } catch (err) {
        if (err instanceof z.ZodError) {
            const firstError = err.errors[0];
            return res.status(400).json({
                error: firstError.message,
                details: err.errors,
            });
        }
        if (err instanceof InviteCodeExhaustedError) {
            return res
                .status(400)
                .json({ error: "This invite code has been fully used" });
        }
        logger.error("Registration error:", err);
        res.status(500).json({ error: "Registration failed" });
    }
});

/**
 * @openapi
 * /api/auth/2fa/setup:
 *   post:
 *     summary: Generate a 2FA secret and QR code for setup
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: 2FA secret and QR code generated
 *       400:
 *         description: 2FA is already enabled
 *       401:
 *         description: Not authenticated
 *       404:
 *         description: User not found
 */
// POST /auth/2fa/setup - Generate 2FA secret and QR code
router.post("/2fa/setup", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { username: true, twoFactorEnabled: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.twoFactorEnabled) {
            return res.status(400).json({ error: "2FA is already enabled" });
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `${BRAND_NAME} (${user.username})`,
            issuer: BRAND_NAME,
        });

        // Generate QR code
        const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

        res.json({
            secret: secret.base32,
            qrCode: qrCodeDataUrl,
        });
    } catch (error) {
        logger.error("2FA setup error:", error);
        res.status(500).json({ error: "Failed to setup 2FA" });
    }
});

/**
 * @openapi
 * /api/auth/2fa/enable:
 *   post:
 *     summary: Verify token and enable 2FA for the current user
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - secret
 *               - token
 *             properties:
 *               secret:
 *                 type: string
 *                 description: The base32-encoded 2FA secret from setup
 *               token:
 *                 type: string
 *                 description: The TOTP token to verify
 *     responses:
 *       200:
 *         description: 2FA enabled, returns recovery codes
 *       400:
 *         description: Secret and token are required
 *       401:
 *         description: Invalid token or not authenticated
 */
// POST /auth/2fa/enable - Verify token and enable 2FA
router.post("/2fa/enable", requireAuth, async (req, res) => {
    try {
        const { secret, token } = req.body;

        if (!secret || !token) {
            return res
                .status(400)
                .json({ error: "Secret and token are required" });
        }

        // Verify the token with the secret
        const verified = speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token,
            window: 2,
        });

        if (!verified) {
            return res
                .status(401)
                .json({ error: "Invalid token. Please try again." });
        }

        // Generate 10 recovery codes
        const recoveryCodes: string[] = [];
        const hashedRecoveryCodes: string[] = [];

        for (let i = 0; i < 10; i++) {
            // Generate 8-character alphanumeric code
            const code = crypto.randomBytes(4).toString("hex").toUpperCase();
            recoveryCodes.push(code);
            // Hash the code before storing
            hashedRecoveryCodes.push(
                crypto.createHash("sha256").update(code).digest("hex")
            );
        }

        // Encrypt the hashed codes for storage
        const encryptedRecoveryCodes = encrypt2FASecret(
            hashedRecoveryCodes.join(",")
        );

        // Encrypt and save the secret
        const encryptedSecret = encrypt2FASecret(secret);
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                twoFactorEnabled: true,
                twoFactorSecret: encryptedSecret,
                twoFactorRecoveryCodes: encryptedRecoveryCodes,
            },
        });

        // Return the plain recovery codes to the user (only time they'll see them)
        res.json({
            message: "2FA enabled successfully",
            recoveryCodes: recoveryCodes,
        });
    } catch (error) {
        logger.error("2FA enable error:", error);
        res.status(500).json({ error: "Failed to enable 2FA" });
    }
});

/**
 * @openapi
 * /api/auth/2fa/disable:
 *   post:
 *     summary: Disable 2FA for the current user
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *               - token
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *               token:
 *                 type: string
 *                 description: Current TOTP token
 *     responses:
 *       200:
 *         description: 2FA disabled successfully
 *       400:
 *         description: Password and token are required
 *       401:
 *         description: Invalid password or token
 *       404:
 *         description: User not found
 */
// POST /auth/2fa/disable - Disable 2FA
router.post("/2fa/disable", requireAuth, async (req, res) => {
    try {
        const { password, token } = req.body;

        if (!password || !token) {
            return res
                .status(400)
                .json({ error: "Password and current 2FA token are required" });
        }

        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (!user.passwordHash) {
            await runDummyBcrypt();
            return res.status(401).json({ error: "Invalid password" });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Verify 2FA token
        if (user.twoFactorSecret) {
            const secret = decrypt2FASecret(user.twoFactorSecret);
            const verified = speakeasy.totp.verify({
                secret,
                encoding: "base32",
                token,
                window: 2,
            });

            if (!verified) {
                return res.status(401).json({ error: "Invalid 2FA token" });
            }
        }

        // Disable 2FA
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                twoFactorEnabled: false,
                twoFactorSecret: null,
                twoFactorRecoveryCodes: null,
            },
        });

        res.json({ message: "2FA disabled successfully" });
    } catch (error) {
        logger.error("2FA disable error:", error);
        res.status(500).json({ error: "Failed to disable 2FA" });
    }
});

/**
 * @openapi
 * /api/auth/2fa/status:
 *   get:
 *     summary: Check if 2FA is enabled for the current user
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: 2FA status
 *       401:
 *         description: Not authenticated
 *       404:
 *         description: User not found
 */
// GET /auth/2fa/status - Check if 2FA is enabled
router.get("/2fa/status", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { twoFactorEnabled: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ enabled: user.twoFactorEnabled });
    } catch (error) {
        logger.error("2FA status error:", error);
        res.status(500).json({ error: "Failed to get 2FA status" });
    }
});

/**
 * @openapi
 * /auth/app-passwords:
 *   get:
 *     summary: List OpenSubsonic app passwords
 *     description: Lists app-password metadata for the authenticated user. Secrets are never returned.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: App-password metadata
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 appPasswords:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       displayName:
 *                         type: string
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *                       lastUsedAt:
 *                         type: string
 *                         format: date-time
 *                         nullable: true
 *                       revokedAt:
 *                         type: string
 *                         format: date-time
 *                         nullable: true
 */
router.get("/app-passwords", requireAuth, async (req, res) => {
    try {
        const appPasswords = await prisma.appPassword.findMany({
            where: { userId: req.user!.id },
            select: {
                id: true,
                displayName: true,
                createdAt: true,
                lastUsedAt: true,
                revokedAt: true,
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json({ appPasswords });
    } catch (error) {
        logger.error("List app passwords error:", error);
        return res.status(500).json({ error: "Failed to list app passwords" });
    }
});

/**
 * @openapi
 * /auth/app-passwords:
 *   post:
 *     summary: Create an OpenSubsonic app password
 *     description: Creates a hash-only app password and returns the generated secret once.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - displayName
 *             properties:
 *               displayName:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 64
 *     responses:
 *       201:
 *         description: Created app password. The secret is shown once.
 *       400:
 *         description: Invalid display name
 */
router.post("/app-passwords", requireAuth, async (req, res) => {
    try {
        const { displayName } = appPasswordSchema.parse(req.body);
        const secret = generateAppPasswordSecret();
        const passwordHash = await bcrypt.hash(secret, 10);

        const appPassword = await prisma.appPassword.create({
            data: {
                userId: req.user!.id,
                displayName,
                passwordHash,
            },
            select: {
                id: true,
                displayName: true,
                createdAt: true,
                lastUsedAt: true,
                revokedAt: true,
            },
        });

        return res.status(201).json({
            appPassword: {
                ...appPassword,
                secret,
            },
        });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({
                error: "Display name must be between 1 and 64 characters",
            });
        }
        logger.error("Create app password error:", error);
        return res.status(500).json({ error: "Failed to create app password" });
    }
});

/**
 * @openapi
 * /auth/app-passwords/{id}:
 *   delete:
 *     summary: Revoke an OpenSubsonic app password
 *     description: Revokes one of the authenticated user's app passwords.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: App password revoked
 *       404:
 *         description: App password not found
 */
router.delete("/app-passwords/:id", requireAuth, async (req, res) => {
    try {
        const revoked = await prisma.appPassword.updateMany({
            where: {
                id: req.params.id,
                userId: req.user!.id,
                revokedAt: null,
            },
            data: { revokedAt: new Date() },
        });

        if (revoked.count === 0) {
            return res.status(404).json({ error: "App password not found" });
        }

        return res.json({ message: "App password revoked" });
    } catch (error) {
        logger.error("Revoke app password error:", error);
        return res.status(500).json({ error: "Failed to revoke app password" });
    }
});

/**
 * @openapi
 * /api/auth/subsonic-password:
 *   get:
 *     summary: Check if a Subsonic password is configured
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: Subsonic password status
 *       401:
 *         description: Not authenticated
 *       404:
 *         description: User not found
 */
// GET /auth/subsonic-password - Check if Subsonic password is configured
router.get("/subsonic-password", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { subsonicPassword: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.json({ hasPassword: Boolean(user.subsonicPassword) });
    } catch (error) {
        logger.error("Subsonic password status error:", error);
        return res
            .status(500)
            .json({ error: "Failed to get Subsonic password status" });
    }
});

/**
 * @openapi
 * /api/auth/subsonic-password:
 *   post:
 *     summary: Set or update the Subsonic password
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 maxLength: 128
 *     responses:
 *       200:
 *         description: Subsonic password set successfully
 *       400:
 *         description: Invalid password
 *       401:
 *         description: Not authenticated
 */
// POST /auth/subsonic-password - Set Subsonic password
router.post("/subsonic-password", requireAuth, async (req, res) => {
    try {
        const { password } = subsonicPasswordSchema.parse(req.body);

        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                subsonicPassword: encrypt(password),
            },
        });

        return res.json({ success: true });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({
                error: "Password must be between 8 and 128 characters",
            });
        }
        logger.error("Set Subsonic password error:", error);
        return res.status(500).json({ error: "Failed to set Subsonic password" });
    }
});

/**
 * @openapi
 * /api/auth/subsonic-password:
 *   delete:
 *     summary: Clear the Subsonic password
 *     tags: [Authentication]
 *     security:
 *       - sessionAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: Subsonic password deleted successfully
 *       401:
 *         description: Not authenticated
 */
// DELETE /auth/subsonic-password - Clear Subsonic password
router.delete("/subsonic-password", requireAuth, async (req, res) => {
    try {
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                subsonicPassword: null,
            },
        });

        return res.json({ success: true });
    } catch (error) {
        logger.error("Delete Subsonic password error:", error);
        return res
            .status(500)
            .json({ error: "Failed to delete Subsonic password" });
    }
});

export default router;
