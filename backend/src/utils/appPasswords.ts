/**
 * Prefix applied to every generated OpenSubsonic app-password secret.
 *
 * Auth paths use it to skip the bcrypt app-password scan for credentials
 * that cannot be app passwords (for example legacy md5 tokens or local
 * account passwords), keeping `/rest` authentication fast.
 */
export const APP_PASSWORD_SECRET_PREFIX = "ssp_ap_";
