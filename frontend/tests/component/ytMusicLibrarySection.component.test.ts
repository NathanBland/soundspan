import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const playbackState = {
    currentTrack: null as { id: string } | null,
    isPlaying: false,
};

const controlCalls = {
    playTracks: [] as Array<{ tracks: unknown[]; index: number }>,
    pause: 0,
    resume: 0,
};

const trackListRenderState = {
    props: null as Record<string, unknown> | null,
};

mock.module("@/features/home/components/SectionHeader", {
    namedExports: {
        SectionHeader: ({ title }: { title: string }) =>
            React.createElement("h2", null, title),
    },
});

mock.module("@/components/ui/HorizontalCarousel", {
    namedExports: {
        HorizontalCarousel: ({ children }: { children: React.ReactNode }) =>
            React.createElement("div", { "data-testid": "carousel" }, children),
        CarouselItem: ({ children }: { children: React.ReactNode }) =>
            React.createElement("div", { "data-testid": "carousel-item" }, children),
    },
});

mock.module("@/components/ui/YouTubeBadge", {
    namedExports: {
        YouTubeBadge: () => React.createElement("span", null, "YT"),
    },
});

mock.module("@/lib/api", {
    namedExports: {
        api: {
            getBrowseImageUrl: (value: string) =>
                `/browse-img/${encodeURIComponent(value)}`,
        },
    },
});

mock.module("next/link", {
    defaultExport: ({
        href,
        children,
        ...rest
    }: {
        href: string;
        children: React.ReactNode;
    }) => React.createElement("a", { href, ...rest }, children),
});

mock.module("@/lib/audio-state-context", {
    namedExports: {
        useAudioState: () => ({
            currentTrack: playbackState.currentTrack,
        }),
    },
});

mock.module("@/lib/audio-playback-context", {
    namedExports: {
        useAudioPlayback: () => ({
            isPlaying: playbackState.isPlaying,
        }),
    },
});

mock.module("@/lib/audio-controls-context", {
    namedExports: {
        useAudioControls: () => ({
            playTracks: (tracks: unknown[], index: number) => {
                controlCalls.playTracks.push({ tracks, index });
            },
            pause: () => {
                controlCalls.pause += 1;
            },
            resume: () => {
                controlCalls.resume += 1;
            },
        }),
    },
});

mock.module("@/components/track", {
    namedExports: {
        TrackList: (props: Record<string, unknown>) => {
            trackListRenderState.props = props;
            const items = Array.isArray(props.items) ? props.items : [];
            return React.createElement(
                "div",
                { "data-testid": "track-list" },
                `items:${items.length}`
            );
        },
        TrackListHeader: ({ columns }: { columns: Array<{ label: string }> }) =>
            React.createElement(
                "div",
                { "data-testid": "track-list-header" },
                columns.map((column) => column.label).join("|")
            ),
    },
});

const library = {
    source: "ytmusic" as const,
    playlists: [
        {
            playlistId: "pl-1",
            title: "Liked Music",
            description: "Private playlist",
            thumbnailUrl: "https://img.example/pl.jpg",
        },
    ],
    albums: [
        {
            browseId: "MPREb_album1",
            title: "Album One",
            artist: "Artist One",
            thumbnailUrl: "https://img.example/alb.jpg",
        },
    ],
    songs: [
        {
            videoId: "song-1",
            title: "Song One",
            artist: "Artist One",
            album: "Album One",
            duration_seconds: 201,
            thumbnailUrl: "https://img.example/song1.jpg",
        },
        {
            videoId: "song-2",
            title: "Song Two",
            artist: "Artist Two",
            album: "Album Two",
            duration: 180,
        },
    ],
};

beforeEach(() => {
    playbackState.currentTrack = null;
    playbackState.isPlaying = false;
    controlCalls.playTracks = [];
    controlCalls.pause = 0;
    controlCalls.resume = 0;
    trackListRenderState.props = null;
});

test("YtMusicLibrarySection renders linked library cards and playable songs", async () => {
    const { YtMusicLibrarySection } = await import(
        "../../features/explore/components/YtMusicLibrarySection"
    );

    const html = renderToStaticMarkup(
        React.createElement(YtMusicLibrarySection, { library })
    );

    assert.match(html, /Your YouTube Music Library/);
    assert.match(html, /Liked Music/);
    assert.match(html, /href="\/explore\/yt-playlist\/pl-1"/);
    assert.match(html, /Album One/);
    assert.match(html, /href="\/explore\/yt-playlist\/MPREb_album1\?type=album"/);
    assert.match(html, /items:2/);

    const onPlay = trackListRenderState.props?.onPlay as
        | ((song: (typeof library.songs)[number], index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(library.songs[0], 0);

    assert.equal(controlCalls.playTracks.length, 1);
    assert.equal(controlCalls.playTracks[0].index, 0);
    assert.deepEqual(controlCalls.playTracks[0].tracks, [
        {
            id: "yt:song-1",
            title: "Song One",
            artist: { name: "Artist One" },
            album: {
                title: "Album One",
                coverArt: "https://img.example/song1.jpg",
            },
            duration: 201,
            streamSource: "youtube",
            youtubeVideoId: "song-1",
        },
        {
            id: "yt:song-2",
            title: "Song Two",
            artist: { name: "Artist Two" },
            album: {
                title: "Album Two",
                coverArt: undefined,
            },
            duration: 180,
            streamSource: "youtube",
            youtubeVideoId: "song-2",
        },
    ]);
});

test("YtMusicLibrarySection toggles the current library song", async () => {
    const { YtMusicLibrarySection } = await import(
        "../../features/explore/components/YtMusicLibrarySection"
    );

    playbackState.currentTrack = { id: "yt:song-1" };
    playbackState.isPlaying = true;
    renderToStaticMarkup(
        React.createElement(YtMusicLibrarySection, { library })
    );
    let onPlay = trackListRenderState.props?.onPlay as
        | ((song: (typeof library.songs)[number], index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(library.songs[0], 0);
    assert.equal(controlCalls.pause, 1);
    assert.equal(controlCalls.resume, 0);

    playbackState.isPlaying = false;
    renderToStaticMarkup(
        React.createElement(YtMusicLibrarySection, { library })
    );
    onPlay = trackListRenderState.props?.onPlay as
        | ((song: (typeof library.songs)[number], index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(library.songs[0], 0);
    assert.equal(controlCalls.pause, 1);
    assert.equal(controlCalls.resume, 1);
});

test("YtMusicLibrarySection renders nothing for an empty library response", async () => {
    const { YtMusicLibrarySection } = await import(
        "../../features/explore/components/YtMusicLibrarySection"
    );

    const html = renderToStaticMarkup(
        React.createElement(YtMusicLibrarySection, {
            library: { source: "ytmusic", playlists: [], albums: [], songs: [] },
        })
    );

    assert.equal(html, "");
});
