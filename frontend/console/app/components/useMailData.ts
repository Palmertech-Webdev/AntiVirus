"use client";

import { startTransition, useCallback, useEffect, useRef, useState } from "react";

import {
  emptyMailDashboard,
  loadMailDashboard,
  purgeMailMessage,
  releaseMailQuarantineItem,
  type DataSource
} from "../../lib/api";
import type { MailDashboardSnapshot } from "../../lib/types";

export function useMailData() {
  const [snapshot, setSnapshot] = useState<MailDashboardSnapshot>(emptyMailDashboard);
  const [source, setSource] = useState<DataSource>("live");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [mutating, setMutating] = useState(false);
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
        const result = await loadMailDashboard();

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

  const releaseQuarantine = useCallback(
    async (mailQuarantineItemId: string) => {
      setMutating(true);
      try {
        await releaseMailQuarantineItem(mailQuarantineItemId);
        await refreshSnapshot("manual");
      } finally {
        setMutating(false);
      }
    },
    [refreshSnapshot]
  );

  const purgeMessage = useCallback(
    async (mailMessageId: string) => {
      setMutating(true);
      try {
        await purgeMailMessage(mailMessageId);
        await refreshSnapshot("manual");
      } finally {
        setMutating(false);
      }
    },
    [refreshSnapshot]
  );

  return {
    snapshot,
    source,
    loading,
    refreshing,
    mutating,
    refreshSnapshot,
    releaseQuarantine,
    purgeMessage
  };
}
