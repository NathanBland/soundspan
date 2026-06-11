import { api } from "./api";

/**
 * Consumes auth redirect tokens from the current browser URL and cleans them from history.
 */
export function consumeAuthRedirectTokensFromUrl(): boolean {
    if (typeof window === "undefined") {
        return false;
    }

    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get("token");
    const refreshTokenFromUrl = urlParams.get("refreshToken");
    if (!tokenFromUrl) {
        return false;
    }

    api.setToken(tokenFromUrl, refreshTokenFromUrl || undefined);
    const cleanUrl = `${window.location.pathname}${window.location.hash}`;
    window.history.replaceState({}, "", cleanUrl);
    return true;
}
