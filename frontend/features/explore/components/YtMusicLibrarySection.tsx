"use client";

import { useCallback, useMemo } from "react";
import Link from "next/link";
import { SectionHeader } from "@/features/home/components/SectionHeader";
import { YouTubeBadge } from "@/components/ui/YouTubeBadge";
import { HorizontalCarousel, CarouselItem } from "@/components/ui/HorizontalCarousel";
import { TrackList, TrackListHeader } from "@/components/track";
import { api, type YtMusicLibraryAlbum, type YtMusicLibraryPlaylist, type YtMusicLibraryResponse, type YtMusicLibrarySong } from "@/lib/api";
import { useAudioState, type Track } from "@/lib/audio-state-context";
import { useAudioPlayback } from "@/lib/audio-playback-context";
import { useAudioControls } from "@/lib/audio-controls-context";
import type { OverflowConfig, TrackRowItem, TrackRowSlots } from "@/components/track";

interface LibraryCard {
    id: string;
    href: string;
    title: string;
    subtitle: string | null;
    thumbnailUrl: string | null;
}

interface YtMusicLibrarySectionProps {
    library: YtMusicLibraryResponse | null;
}

function normalizeString(value: unknown): string | null {
    return typeof value === "string" && value.trim().length > 0
        ? value.trim()
        : null;
}

function resolveThumbnailUrl(item: {
    thumbnailUrl?: string | null;
    thumbnails?: Array<{ url?: string; width?: number }>;
}): string | null {
    const flattened = normalizeString(item.thumbnailUrl);
    if (flattened) return flattened;

    const thumbnail = item.thumbnails?.find((candidate) =>
        Boolean(candidate.url && (candidate.width ?? 0) >= 200)
    ) ?? item.thumbnails?.find((candidate) => Boolean(candidate.url));

    return normalizeString(thumbnail?.url);
}

function resolveSongVideoId(song: YtMusicLibrarySong): string | null {
    const videoId = normalizeString(song.videoId);
    if (videoId) return videoId;

    const id = normalizeString(song.id);
    if (!id) return null;

    return id.startsWith("yt:") ? id.slice(3) : id;
}

function resolveTitle(item: { title?: string; name?: string }, fallback: string): string {
    return normalizeString(item.title) ?? normalizeString(item.name) ?? fallback;
}

function resolveArtistName(item: {
    artist?: string;
    artists?: Array<string | { name?: string }>;
}): string {
    const artist = normalizeString(item.artist);
    if (artist) return artist;

    for (const entry of item.artists ?? []) {
        const name = typeof entry === "string" ? entry : entry.name;
        const normalized = normalizeString(name);
        if (normalized) return normalized;
    }

    return "Unknown Artist";
}

function resolveAlbumTitle(song: YtMusicLibrarySong): string {
    if (typeof song.album === "string") {
        return normalizeString(song.album) ?? "Single";
    }

    return normalizeString(song.album?.title)
        ?? normalizeString(song.album?.name)
        ?? "Single";
}

function parseDurationString(rawDuration: string): number {
    const parts = rawDuration.split(":").map((part) => Number.parseInt(part, 10));
    if (parts.length === 0 || parts.some((part) => !Number.isFinite(part))) {
        return 0;
    }

    return parts.reduce((total, part) => total * 60 + part, 0);
}

function resolveDuration(song: YtMusicLibrarySong): number {
    if (typeof song.duration_seconds === "number") {
        return song.duration_seconds;
    }
    if (typeof song.duration === "number") {
        return song.duration;
    }
    if (typeof song.duration === "string") {
        return parseDurationString(song.duration);
    }
    return 0;
}

function librarySongToQueueTrack(song: YtMusicLibrarySong): Track {
    const videoId = resolveSongVideoId(song) ?? "";
    const thumbnailUrl = resolveThumbnailUrl(song);
    return {
        id: `yt:${videoId}`,
        title: resolveTitle(song, "Untitled Song"),
        artist: { name: resolveArtistName(song) },
        album: {
            title: resolveAlbumTitle(song),
            coverArt: thumbnailUrl || undefined,
        },
        duration: resolveDuration(song),
        streamSource: "youtube",
        youtubeVideoId: videoId,
    };
}

function librarySongToRowItem(song: YtMusicLibrarySong): TrackRowItem {
    const videoId = resolveSongVideoId(song) ?? "";
    const thumbnailUrl = resolveThumbnailUrl(song);
    return {
        id: `yt:${videoId}`,
        title: resolveTitle(song, "Untitled Song"),
        artistName: resolveArtistName(song),
        duration: resolveDuration(song),
        coverArtUrl: thumbnailUrl ? api.getBrowseImageUrl(thumbnailUrl) : null,
    };
}

function playlistToCard(playlist: YtMusicLibraryPlaylist, index: number): LibraryCard | null {
    const playlistId =
        normalizeString(playlist.playlistId)
        ?? normalizeString(playlist.browseId)
        ?? normalizeString(playlist.id);
    if (!playlistId) return null;

    const count = playlist.trackCount ?? playlist.count;
    const countText = count === undefined || count === null ? null : `${count} tracks`;
    return {
        id: playlistId,
        href: `/explore/yt-playlist/${encodeURIComponent(playlistId)}`,
        title: resolveTitle(playlist, `Playlist ${index + 1}`),
        subtitle: normalizeString(playlist.description)
            ?? normalizeString(playlist.author)
            ?? countText,
        thumbnailUrl: resolveThumbnailUrl(playlist),
    };
}

function albumToCard(album: YtMusicLibraryAlbum, index: number): LibraryCard | null {
    const browseId =
        normalizeString(album.browseId)
        ?? normalizeString(album.albumId)
        ?? normalizeString(album.playlistId)
        ?? normalizeString(album.id);
    if (!browseId) return null;

    return {
        id: browseId,
        href: `/explore/yt-playlist/${encodeURIComponent(browseId)}?type=album`,
        title: resolveTitle(album, `Album ${index + 1}`),
        subtitle: resolveArtistName(album),
        thumbnailUrl: resolveThumbnailUrl(album),
    };
}

function LibraryCards({ items }: { items: LibraryCard[] }) {
    return (
        <HorizontalCarousel gap="lg">
            {items.map((item) => (
                <CarouselItem key={item.id}>
                    <Link href={item.href} className="group">
                        <div className="aspect-square rounded-md bg-white/5 overflow-hidden mb-2">
                            {item.thumbnailUrl && (
                                // eslint-disable-next-line @next/next/no-img-element -- matches sibling browse cards that render proxied provider images.
                                <img
                                    src={api.getBrowseImageUrl(item.thumbnailUrl)}
                                    alt={item.title}
                                    className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                                />
                            )}
                        </div>
                        <p className="text-sm text-white truncate">{item.title}</p>
                        {item.subtitle && (
                            <p className="text-xs text-gray-400 truncate">
                                {item.subtitle}
                            </p>
                        )}
                    </Link>
                </CarouselItem>
            ))}
        </HorizontalCarousel>
    );
}

/**
 * Renders linked-account YouTube Music library previews on Explore.
 */
export function YtMusicLibrarySection({ library }: YtMusicLibrarySectionProps) {
    const { currentTrack } = useAudioState();
    const { isPlaying } = useAudioPlayback();
    const { playTracks, pause, resume } = useAudioControls();

    const playlists = useMemo(
        () => (library?.playlists ?? [])
            .map(playlistToCard)
            .filter((item): item is LibraryCard => Boolean(item)),
        [library?.playlists],
    );
    const albums = useMemo(
        () => (library?.albums ?? [])
            .map(albumToCard)
            .filter((item): item is LibraryCard => Boolean(item)),
        [library?.albums],
    );
    const songs = useMemo(
        () => (library?.songs ?? []).filter((song) => Boolean(resolveSongVideoId(song))),
        [library?.songs],
    );

    const handlePlay = useCallback(
        (song: YtMusicLibrarySong, index: number) => {
            const videoId = resolveSongVideoId(song);
            if (!videoId) return;

            const trackId = `yt:${videoId}`;
            if (currentTrack?.id === trackId) {
                if (isPlaying) {
                    pause();
                } else {
                    resume();
                }
                return;
            }

            playTracks(songs.map(librarySongToQueueTrack), index);
        },
        [currentTrack?.id, isPlaying, pause, playTracks, resume, songs],
    );

    const rowSlots = useCallback(
        (song: YtMusicLibrarySong): TrackRowSlots => ({
            titleBadges: <YouTubeBadge />,
            middleColumns: (
                <p className="hidden md:flex items-center text-sm text-gray-400 truncate">
                    {resolveAlbumTitle(song)}
                </p>
            ),
        }),
        [],
    );

    const rowOverflow = useCallback(
        (song: YtMusicLibrarySong): OverflowConfig => ({
            track: librarySongToQueueTrack(song),
            showGoToArtist: false,
            showGoToAlbum: false,
            showMatchVibe: false,
            showStartRadio: false,
        }),
        [],
    );

    if (playlists.length === 0 && albums.length === 0 && songs.length === 0) {
        return null;
    }

    return (
        <section className="space-y-5">
            <SectionHeader title="Your YouTube Music Library" badge={<YouTubeBadge />} />

            {playlists.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                        Playlists
                    </h3>
                    <LibraryCards items={playlists} />
                </div>
            )}

            {albums.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                        Albums
                    </h3>
                    <LibraryCards items={albums} />
                </div>
            )}

            {songs.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                        Songs
                    </h3>
                    <TrackList
                        items={songs}
                        toRowItem={librarySongToRowItem}
                        onPlay={handlePlay}
                        getKey={(song, index) =>
                            resolveSongVideoId(song) ?? `${resolveTitle(song, "song")}-${index}`
                        }
                        rowSlots={rowSlots}
                        rowOverflow={rowOverflow}
                        rowClassName="grid-cols-[28px_1fr_auto] md:grid-cols-[40px_minmax(200px,2fr)_minmax(100px,1fr)_auto]"
                        accentColor="#ef4444"
                        preferenceMode="up-only"
                        tvSection="explore-ytmusic-library-songs"
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
                </div>
            )}
        </section>
    );
}
