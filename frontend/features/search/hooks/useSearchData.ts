import {
    useSearchQuery,
    useDiscoverSearchQuery,
    useDiscoverSimilarArtistsQuery,
    useYtMusicSearchQuery,
} from "@/hooks/useQueries";
import type { SearchResult, DiscoverResult, AliasInfo } from "../types";
import { useMemo } from "react";
import type { CanonicalMediaSearchResult } from "@soundspan/media-metadata-contract";

interface UseSearchDataProps {
    query: string;
    libraryType?: "all" | "artists" | "albums" | "tracks" | "audiobooks" | "podcasts";
    discoverType?: "music" | "podcasts" | "all";
    libraryLimit?: number;
    discoverLimit?: number;
    similarArtistsLimit?: number;
}

interface UseSearchDataReturn {
    libraryResults: SearchResult | null;
    discoverResults: DiscoverResult[];
    similarArtists: DiscoverResult[];
    ytMusicResults: CanonicalMediaSearchResult[];
    aliasInfo: AliasInfo | null;
    isLibrarySearching: boolean;
    isDiscoverSearching: boolean;
    isYtMusicSearching: boolean;
    hasSearched: boolean;
}

/**
 * Executes useSearchData.
 */
export function useSearchData({
    query,
    libraryType = "all",
    discoverType = "all",
    libraryLimit = 20,
    discoverLimit = 20,
    similarArtistsLimit = 6,
}: UseSearchDataProps): UseSearchDataReturn {
    const ytMusicEnabledForSearch = discoverType !== "podcasts";
    const {
        data: libraryResults,
        isLoading: isLibrarySearching,
        isFetching: isLibraryFetching
    } = useSearchQuery(query, libraryType, libraryLimit);

    const {
        data: discoverData,
        isLoading: isDiscoverSearching,
        isFetching: isDiscoverFetching
    } = useDiscoverSearchQuery(query, discoverType, discoverLimit);

    const {
        data: ytMusicData,
        isLoading: isYtMusicLoading,
        isFetching: isYtMusicFetching,
    } = useYtMusicSearchQuery(query, "songs", {
        enabled: ytMusicEnabledForSearch,
    });

    const discoverResults = useMemo(() => {
        return discoverData?.results || [];
    }, [discoverData]);

    const aliasInfo = useMemo(() => {
        return discoverData?.aliasInfo || null;
    }, [discoverData]);

    // Derive top artist for the similar artists query
    const topArtist = useMemo(() => {
        const first = discoverResults.find((r) => r.type === "music");
        return first ? { name: first.name, mbid: first.mbid || "" } : null;
    }, [discoverResults]);

    // Separate query for similar artists -- fires after discover results load
    const { data: similarData } = useDiscoverSimilarArtistsQuery(
        topArtist?.name || "",
        topArtist?.mbid || "",
        similarArtistsLimit
    );

    const similarArtists = useMemo(() => {
        return similarData?.similarArtists || [];
    }, [similarData]);

    const ytMusicResults = useMemo(() => {
        if (!ytMusicEnabledForSearch) {
            return [];
        }
        return ytMusicData?.results || [];
    }, [ytMusicData, ytMusicEnabledForSearch]);

    const hasSearched = query.trim().length >= 2;

    return {
        libraryResults: libraryResults || null,
        discoverResults,
        similarArtists,
        ytMusicResults,
        aliasInfo,
        isLibrarySearching: isLibrarySearching || isLibraryFetching,
        isDiscoverSearching: isDiscoverSearching || isDiscoverFetching,
        isYtMusicSearching:
            ytMusicEnabledForSearch && (isYtMusicLoading || isYtMusicFetching),
        hasSearched,
    };
}
