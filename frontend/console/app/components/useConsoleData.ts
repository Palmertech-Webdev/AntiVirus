"use client";

import { startTransition, useCallback, useEffect, useRef, useState } from "react";

import { loadDashboard, type DataSource } from "../../lib/api";
import { emptyDashboard } from "../../lib/mock-data";
import type { DashboardSnapshot } from "../../lib/types";

export function useConsoleData() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(emptyDashboard);
  const [source, setSource] = useState<DataSource>("live");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const requestInFlightRef = useRef<Promise<void> | null>(null);

  const refreshSnapshot = useCallback(async (mode: "initial" | "poll" | "manual") => {
    if (requestInFlightRef.current) {
      return requestInFlightRef.current;
    }

    if (mode !== "poll") {
      setRefreshing(true);
    }

    const request = (async () => {
      try {
        const result = await loadDashboard();

        startTransition(() => {
          setSnapshot(result.data);
          setSource(result.source);
          setLoading(false);
        });
      } catch {
        startTransition(() => {
          setLoading(false);
        });
      } finally {
        requestInFlightRef.current = null;
        setRefreshing(false);
      }
    })();

    requestInFlightRef.current = request;
    return request;
  }, []);

  useEffect(() => {
    void refreshSnapshot("initial");
    const intervalId = window.setInterval(() => {
      void refreshSnapshot("poll");
    }, 60000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [refreshSnapshot]);

  return {
    snapshot,
    source,
    loading,
    refreshing,
    refreshSnapshot
  };
}
