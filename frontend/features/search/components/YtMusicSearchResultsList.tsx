"use client";

import { useCallback } from "react";
import type { CanonicalMediaSearchResult } from "@soundspan/media-metadata-contract";
import { api } from "@/lib/api";
import { useAudioState, type Track } from "@/lib/audio-state-context";
import { useAudioPlayback } from "@/lib/audio-playback-context";
import { useAudioControls } from "@/lib/audio-controls-context";
import { YouTubeBadge } from "@/components/ui/YouTubeBadge";
import { TrackList, TrackListHeader } from "@/components/track";
import type { OverflowConfig, TrackRowItem, TrackRowSlots } from "@/components/track";

interface YtMusicSearchResultsListProps {
    results: CanonicalMediaSearchResult[];
    limit?: number | null;
}

function resultToQueueTrack(result: CanonicalMediaSearchResult): Track {
    return {
        id: `yt:${result.providerTrackId}`,
        title: result.title,
        artist: { name: result.artistName || "Unknown Artist" },
        album: {
            title: result.albumTitle || "Single",
            coverArt: result.thumbnailUrl || undefined,
        },
        duration: result.durationSec ?? 0,
        streamSource: "youtube",
        youtubeVideoId: result.providerTrackId,
    };
}

function resultToRowItem(result: CanonicalMediaSearchResult): TrackRowItem {
    return {
        id: `yt:${result.providerTrackId}`,
        title: result.title,
        artistName: result.artistName || "Unknown Artist",
        duration: result.durationSec ?? 0,
        coverArtUrl: result.thumbnailUrl
            ? api.getBrowseImageUrl(result.thumbnailUrl)
            : null,
    };
}

/**
 * Renders YouTube Music song results in the global search page.
 */
export function YtMusicSearchResultsList({
    results,
    limit = 10,
}: YtMusicSearchResultsListProps) {
    const { currentTrack } = useAudioState();
    const { isPlaying } = useAudioPlayback();
    const { playTracks, pause, resume } = useAudioControls();
    const allResults = results;
    const visibleResults =
        typeof limit === "number" ? allResults.slice(0, limit) : allResults;

    const handlePlay = useCallback(
        (result: CanonicalMediaSearchResult, index: number) => {
            const trackId = `yt:${result.providerTrackId}`;
            if (currentTrack?.id === trackId) {
                if (isPlaying) {
                    pause();
                } else {
                    resume();
                }
                return;
            }

            playTracks(allResults.map(resultToQueueTrack), index);
        },
        [allResults, currentTrack?.id, isPlaying, playTracks, pause, resume],
    );

    const rowSlots = useCallback(
        (result: CanonicalMediaSearchResult): TrackRowSlots => ({
            titleBadges: <YouTubeBadge />,
            middleColumns: (
                <p className="hidden md:flex items-center text-sm text-gray-400 truncate">
                    {result.albumTitle || "Single"}
                </p>
            ),
        }),
        [],
    );

    const rowOverflow = useCallback(
        (result: CanonicalMediaSearchResult): OverflowConfig => ({
            track: resultToQueueTrack(result),
            showGoToArtist: false,
            showGoToAlbum: false,
            showMatchVibe: false,
            showStartRadio: false,
        }),
        [],
    );

    if (allResults.length === 0) {
        return null;
    }

    return (
        <section>
            <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <span>YouTube Music</span>
                <YouTubeBadge />
            </h2>
            <TrackList
                items={visibleResults}
                toRowItem={resultToRowItem}
                onPlay={handlePlay}
                rowSlots={rowSlots}
                rowOverflow={rowOverflow}
                rowClassName="grid-cols-[28px_1fr_auto] md:grid-cols-[40px_minmax(200px,2fr)_minmax(100px,1fr)_auto]"
                accentColor="#ef4444"
                preferenceMode="up-only"
                tvSection="search-results-ytmusic"
                className="space-y-1"
                header={
                    <TrackListHeader
                        className="grid-cols-[40px_minmax(200px,2fr)_minmax(100px,1fr)_auto] gap-4 mb-2"
                        columns={[
                            { label: "#", className: "text-center" },
                            { label: "Title" },
                            { label: "Album" },
                            { label: "" },
                        ]}
                    />
                }
            />
        </section>
    );
}
