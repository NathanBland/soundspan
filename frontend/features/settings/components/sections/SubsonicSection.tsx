"use client";

import { useEffect, useState } from "react";
import { Copy, Info, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { InlineStatus, StatusType } from "@/components/ui/InlineStatus";
import { SettingsInput, SettingsRow } from "../ui";
import { BRAND_NAME } from "@/lib/brand";

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

interface AppPassword {
    id: string;
    displayName: string;
    createdAt: string;
    lastUsedAt: string | null;
    revokedAt: string | null;
}

function formatDate(value: string | null): string {
    if (!value) return "Never";
    return new Date(value).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
    });
}

/**
 * OpenSubsonic client access rows rendered inside AccountSection.
 * Self-contained state management, no SettingsSection wrapper.
 */
export function SubsonicRows() {
    const { user } = useAuth();

    const [appPasswords, setAppPasswords] = useState<AppPassword[]>([]);
    const [appPasswordName, setAppPasswordName] = useState("");
    const [generatedSecret, setGeneratedSecret] = useState("");
    const [copied, setCopied] = useState(false);
    const [creating, setCreating] = useState(false);
    const [revokingId, setRevokingId] = useState<string | null>(null);
    const [appStatus, setAppStatus] = useState<StatusType>("idle");
    const [appMessage, setAppMessage] = useState("");

    const [password, setPassword] = useState("");
    const [hasPassword, setHasPassword] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [status, setStatus] = useState<StatusType>("idle");
    const [message, setMessage] = useState("");
    const [showTooltip, setShowTooltip] = useState(false);
    const [showLegacy, setShowLegacy] = useState(false);

    const loadAppPasswords = async () => {
        try {
            const result = await api.listAppPasswords();
            setAppPasswords(result.appPasswords);
        } catch {
            // Preserve settings page rendering even if endpoint is unavailable.
        }
    };

    useEffect(() => {
        const loadStatus = async () => {
            try {
                const result = await api.getSubsonicPasswordStatus();
                setHasPassword(result.hasPassword);
            } catch {
                // Preserve settings page rendering even if endpoint is unavailable.
            }
        };

        loadStatus();
        loadAppPasswords();
    }, []);

    const handleCreateAppPassword = async () => {
        const trimmedName = appPasswordName.trim();
        if (!trimmedName) {
            setAppStatus("error");
            setAppMessage("Name required");
            return;
        }

        setCreating(true);
        setAppStatus("loading");

        try {
            const result = await api.createAppPassword(trimmedName);
            setGeneratedSecret(result.appPassword.secret);
            setAppPasswordName("");
            setCopied(false);
            setAppStatus("success");
            setAppMessage("Created");
            await loadAppPasswords();
        } catch (error) {
            setAppStatus("error");
            setAppMessage(error instanceof Error ? error.message : "Failed");
        } finally {
            setCreating(false);
        }
    };

    const handleRevokeAppPassword = async (id: string) => {
        setRevokingId(id);
        setAppStatus("loading");

        try {
            await api.revokeAppPassword(id);
            setAppStatus("success");
            setAppMessage("Revoked");
            await loadAppPasswords();
        } catch (error) {
            setAppStatus("error");
            setAppMessage(error instanceof Error ? error.message : "Failed");
        } finally {
            setRevokingId(null);
        }
    };

    const handleCopyGeneratedSecret = async () => {
        if (!generatedSecret) return;
        await navigator.clipboard.writeText(generatedSecret);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleSave = async () => {
        if (!password.trim()) {
            setStatus("error");
            setMessage("Password is required");
            return;
        }

        if (password.length < MIN_PASSWORD_LENGTH) {
            setStatus("error");
            setMessage(`Minimum ${MIN_PASSWORD_LENGTH} characters`);
            return;
        }

        if (password.length > MAX_PASSWORD_LENGTH) {
            setStatus("error");
            setMessage(`Maximum ${MAX_PASSWORD_LENGTH} characters`);
            return;
        }

        setIsSaving(true);
        setStatus("loading");

        try {
            await api.setSubsonicPassword(password);
            setHasPassword(true);
            setPassword("");
            setIsEditing(false);
            setStatus("success");
            setMessage("Saved");
        } catch (error) {
            setStatus("error");
            setMessage(error instanceof Error ? error.message : "Failed");
        } finally {
            setIsSaving(false);
        }
    };

    const handleClear = async () => {
        setIsSaving(true);
        setStatus("loading");

        try {
            await api.clearSubsonicPassword();
            setHasPassword(false);
            setPassword("");
            setIsEditing(false);
            setStatus("success");
            setMessage("Cleared");
        } catch {
            setStatus("error");
            setMessage("Failed");
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <SettingsRow
            label="OpenSubsonic Access"
            align="start"
            labelExtra={
                <span className="relative inline-flex">
                    <button
                        type="button"
                        onMouseEnter={() => setShowTooltip(true)}
                        onMouseLeave={() => setShowTooltip(false)}
                        onClick={() => setShowTooltip((current) => !current)}
                        className="inline-flex items-center rounded p-0.5 text-gray-400 hover:text-white transition-colors"
                        aria-label="OpenSubsonic access info"
                        title="OpenSubsonic access info"
                    >
                        <Info className="h-3.5 w-3.5" />
                    </button>
                    {showTooltip && (
                        <span className="absolute left-0 top-full z-30 mt-1 w-72 rounded-md border border-white/15 bg-[#141414] p-2 text-[11px] leading-relaxed text-gray-300 shadow-2xl">
                            App passwords are scoped to third-party OpenSubsonic clients and
                            cannot sign in to the {BRAND_NAME} web app.
                        </span>
                    )}
                </span>
            }
            description={`Use username ${user?.username || "your account"} with a generated app password in compatible clients.`}
        >
            <div className="w-full max-w-3xl space-y-4">
                <div className="rounded-lg border border-white/10 bg-white/[0.03] p-4 space-y-3">
                    <div className="flex flex-col gap-3 md:flex-row md:items-end">
                        <div className="md:w-72">
                            <label className="mb-1.5 block text-xs font-medium text-gray-400">
                                Name
                            </label>
                            <SettingsInput
                                id="app-password-name"
                                type="text"
                                value={appPasswordName}
                                onChange={setAppPasswordName}
                                placeholder="e.g. Phone, Desktop client"
                            />
                        </div>
                        <button
                            onClick={handleCreateAppPassword}
                            disabled={!appPasswordName.trim() || creating}
                            className="px-4 py-2 text-sm bg-white text-black rounded-full font-medium hover:scale-105 transition-transform disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {creating ? "Creating..." : "Create App Password"}
                        </button>
                        <InlineStatus
                            status={appStatus}
                            message={appMessage}
                            onClear={() => setAppStatus("idle")}
                        />
                    </div>

                    {generatedSecret && (
                        <div className="rounded-lg border border-yellow-700/50 bg-yellow-900/20 p-3 space-y-2">
                            <p className="text-sm font-medium text-yellow-200">
                                New app password
                            </p>
                            <div className="flex items-center gap-2">
                                <input
                                    type="text"
                                    readOnly
                                    value={generatedSecret}
                                    className="min-w-0 flex-1 rounded border border-yellow-700/50 bg-black/50 px-3 py-2 font-mono text-sm text-white"
                                />
                                <button
                                    onClick={handleCopyGeneratedSecret}
                                    className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-white px-3 py-2 text-sm font-medium text-black hover:scale-105 transition-transform"
                                >
                                    <Copy className="h-4 w-4" />
                                    {copied ? "Copied" : "Copy"}
                                </button>
                            </div>
                            <p className="text-xs text-yellow-200">
                                Save it now. It will not be shown again.
                            </p>
                        </div>
                    )}

                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[520px]">
                            <thead>
                                <tr className="border-b border-white/10">
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                                        Client
                                    </th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                                        Created
                                    </th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                                        Last Used
                                    </th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                                        Status
                                    </th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {appPasswords.length === 0 ? (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            className="px-3 py-5 text-center text-sm text-gray-400"
                                        >
                                            No app passwords yet
                                        </td>
                                    </tr>
                                ) : (
                                    appPasswords.map((entry) => {
                                        const revoked = Boolean(entry.revokedAt);
                                        return (
                                            <tr
                                                key={entry.id}
                                                className="border-b border-white/5"
                                            >
                                                <td className="px-3 py-2 text-sm text-white">
                                                    {entry.displayName}
                                                </td>
                                                <td className="px-3 py-2 text-sm text-gray-400">
                                                    {formatDate(entry.createdAt)}
                                                </td>
                                                <td className="px-3 py-2 text-sm text-gray-400">
                                                    {formatDate(entry.lastUsedAt)}
                                                </td>
                                                <td className="px-3 py-2 text-sm text-gray-400">
                                                    {revoked ? "Revoked" : "Active"}
                                                </td>
                                                <td className="px-3 py-2 text-sm">
                                                    {!revoked && (
                                                        <button
                                                            onClick={() => handleRevokeAppPassword(entry.id)}
                                                            disabled={revokingId === entry.id}
                                                            className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-sm text-red-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50"
                                                        >
                                                            <Trash2 className="h-4 w-4" />
                                                            Revoke
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="border-t border-white/10 pt-3">
                    <button
                        type="button"
                        onClick={() => setShowLegacy((current) => !current)}
                        className="text-sm text-gray-400 hover:text-white transition-colors"
                    >
                        {showLegacy ? "Hide" : "Show"} legacy Subsonic password
                    </button>

                    {showLegacy && (
                        <div className="mt-3 flex flex-wrap items-center gap-3">
                            {hasPassword && !isEditing ? (
                                <>
                                    <div className="w-64">
                                        <input
                                            id="subsonic-password"
                                            type="text"
                                            value="••••••••"
                                            disabled
                                            className="w-full bg-[#333] text-white text-sm px-3 py-2 rounded-md border-0 outline-none opacity-50 cursor-not-allowed"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setIsEditing(true)}
                                        className="text-sm text-gray-400 hover:text-white transition-colors"
                                    >
                                        Change
                                    </button>
                                    <button
                                        onClick={handleClear}
                                        disabled={isSaving}
                                        className="text-sm text-gray-400 hover:text-white transition-colors disabled:opacity-50"
                                    >
                                        Clear
                                    </button>
                                </>
                            ) : (
                                <>
                                    <div className="w-64">
                                        <SettingsInput
                                            id="subsonic-password"
                                            type="password"
                                            value={password}
                                            onChange={setPassword}
                                            placeholder="Enter legacy password"
                                        />
                                    </div>
                                    <button
                                        onClick={handleSave}
                                        disabled={!password.trim() || isSaving}
                                        className="px-4 py-2 text-sm bg-white text-black rounded-full font-medium hover:scale-105 transition-transform disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {isSaving ? "Saving..." : "Save"}
                                    </button>
                                    {hasPassword && (
                                        <button
                                            onClick={() => {
                                                setIsEditing(false);
                                                setPassword("");
                                            }}
                                            className="text-sm text-gray-400 hover:text-white transition-colors"
                                        >
                                            Cancel
                                        </button>
                                    )}
                                </>
                            )}
                            <InlineStatus
                                status={status}
                                message={message}
                                onClear={() => setStatus("idle")}
                            />
                        </div>
                    )}
                </div>
            </div>
        </SettingsRow>
    );
}
