import "express-session";

declare module "express-session" {
    interface SessionData {
        userId: string;
        oidc?: {
            state: string;
            nonce: string;
            codeVerifier: string;
            returnTo: string;
        };
    }
}
