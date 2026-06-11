export interface AuthLoginConfig {
    oidcEnabled: boolean;
    localLoginEnabled: boolean;
}

/** Resolves which login controls should be visible for the current auth config. */
export function resolveAuthLoginMode(config: AuthLoginConfig) {
    return {
        showSsoButton: config.oidcEnabled,
        showLocalForm: config.localLoginEnabled,
        showSeparator: config.oidcEnabled && config.localLoginEnabled,
    };
}
