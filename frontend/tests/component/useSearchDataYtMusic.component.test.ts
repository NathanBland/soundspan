import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";

const calls = {
    ytMusicSearch: [] as Array<Record<string, unknown>>,
};

const ytMusicSearchData = {
    results: [
        {
            source: "youtube",
            provider: "ytmusic",
            providerTrackId: "yt-1",
            title: "Everything In Its Right Place",
            artistName: "Radiohead",
            albumTitle: "Kid A",
            durationSec: 251,
            thumbnailUrl: "https://img.example/yt-1.jpg",
            raw: {},
        },
    ],
};

mock.module("react", {
    namedExports: {
        useMemo: <T>(factory: () => T) => factory(),
    },
});

mock.module("@/hooks/useQueries", {
    namedExports: {
        useSearchQuery: () => ({
            data: null,
            isLoading: false,
            isFetching: false,
        }),
        useDiscoverSearchQuery: () => ({
            data: { results: [], aliasInfo: null },
            isLoading: false,
            isFetching: false,
        }),
        useDiscoverSimilarArtistsQuery: () => ({
            data: { similarArtists: [] },
        }),
        useYtMusicSearchQuery: (
            query: string,
            filter: string,
            options?: { enabled?: boolean },
        ) => {
            calls.ytMusicSearch.push({ query, filter, enabled: options?.enabled });
            return {
                data: ytMusicSearchData,
                isLoading: false,
                isFetching: false,
            };
        },
    },
});

beforeEach(() => {
    calls.ytMusicSearch = [];
});

test("useSearchData includes YouTube Music search for normal music searches", async () => {
    const { useSearchData } = await import(
        "../../features/search/hooks/useSearchData"
    );

    const result = useSearchData({
        query: "radiohead",
        discoverType: "all",
    });

    assert.deepEqual(calls.ytMusicSearch, [
        { query: "radiohead", filter: "songs", enabled: true },
    ]);
    assert.deepEqual(result.ytMusicResults, ytMusicSearchData.results);
    assert.equal(result.isYtMusicSearching, false);
});

test("useSearchData disables YouTube Music search for podcast-only searches", async () => {
    const { useSearchData } = await import(
        "../../features/search/hooks/useSearchData"
    );

    const result = useSearchData({
        query: "history",
        discoverType: "podcasts",
    });

    assert.deepEqual(calls.ytMusicSearch, [
        { query: "history", filter: "songs", enabled: false },
    ]);
    assert.deepEqual(result.ytMusicResults, []);
    assert.equal(result.isYtMusicSearching, false);
});
