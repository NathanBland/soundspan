import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { CanonicalMediaSearchResult } from "@soundspan/media-metadata-contract";

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

function buildResult(id: string): CanonicalMediaSearchResult {
    return {
        source: "youtube",
        provider: "ytmusic",
        providerTrackId: id,
        title: `Song ${id}`,
        artistName: `Artist ${id}`,
        albumTitle: `Album ${id}`,
        durationSec: 180,
        thumbnailUrl: `https://img.example/${id}.jpg`,
        raw: {},
    };
}

beforeEach(() => {
    playbackState.currentTrack = null;
    playbackState.isPlaying = false;
    controlCalls.playTracks = [];
    controlCalls.pause = 0;
    controlCalls.resume = 0;
    trackListRenderState.props = null;
});

test("YtMusicSearchResultsList renders limited rows and queues all provider tracks", async () => {
    const { YtMusicSearchResultsList } = await import(
        "../../features/search/components/YtMusicSearchResultsList"
    );
    const results = [buildResult("yt-1"), buildResult("yt-2")];

    const html = renderToStaticMarkup(
        React.createElement(YtMusicSearchResultsList, {
            results,
            limit: 1,
        })
    );

    assert.match(html, /YouTube Music/);
    assert.match(html, /items:1/);

    const onPlay = trackListRenderState.props?.onPlay as
        | ((result: CanonicalMediaSearchResult, index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(results[0], 0);

    assert.equal(controlCalls.playTracks.length, 1);
    assert.equal(controlCalls.playTracks[0].index, 0);
    assert.deepEqual(controlCalls.playTracks[0].tracks, [
        {
            id: "yt:yt-1",
            title: "Song yt-1",
            artist: { name: "Artist yt-1" },
            album: {
                title: "Album yt-1",
                coverArt: "https://img.example/yt-1.jpg",
            },
            duration: 180,
            streamSource: "youtube",
            youtubeVideoId: "yt-1",
        },
        {
            id: "yt:yt-2",
            title: "Song yt-2",
            artist: { name: "Artist yt-2" },
            album: {
                title: "Album yt-2",
                coverArt: "https://img.example/yt-2.jpg",
            },
            duration: 180,
            streamSource: "youtube",
            youtubeVideoId: "yt-2",
        },
    ]);
});

test("YtMusicSearchResultsList toggles the current provider track", async () => {
    const { YtMusicSearchResultsList } = await import(
        "../../features/search/components/YtMusicSearchResultsList"
    );
    const results = [buildResult("yt-1")];

    playbackState.currentTrack = { id: "yt:yt-1" };
    playbackState.isPlaying = true;
    renderToStaticMarkup(
        React.createElement(YtMusicSearchResultsList, { results })
    );
    let onPlay = trackListRenderState.props?.onPlay as
        | ((result: CanonicalMediaSearchResult, index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(results[0], 0);
    assert.equal(controlCalls.pause, 1);
    assert.equal(controlCalls.resume, 0);
    assert.equal(controlCalls.playTracks.length, 0);

    playbackState.isPlaying = false;
    renderToStaticMarkup(
        React.createElement(YtMusicSearchResultsList, { results })
    );
    onPlay = trackListRenderState.props?.onPlay as
        | ((result: CanonicalMediaSearchResult, index: number) => void)
        | undefined;
    assert.ok(onPlay);
    onPlay(results[0], 0);
    assert.equal(controlCalls.pause, 1);
    assert.equal(controlCalls.resume, 1);
    assert.equal(controlCalls.playTracks.length, 0);
});
