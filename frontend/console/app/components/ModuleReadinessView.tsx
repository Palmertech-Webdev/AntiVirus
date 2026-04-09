"use client";

import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { buildConsoleViewModel, type NavigationKey } from "../../lib/console-model";
import { useConsoleData } from "./useConsoleData";

interface ModuleReadinessViewProps {
  activeNav: NavigationKey;
  title: string;
  subtitle: string;
  searchPlaceholder: string;
  readinessTitle: string;
  readinessCopy: string;
  integrationTargets: Array<{ title: string; detail: string }>;
}

export default function ModuleReadinessView({
  activeNav,
  title,
  subtitle,
  searchPlaceholder,
  readinessTitle,
  readinessCopy,
  integrationTargets
}: ModuleReadinessViewProps) {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const model = buildConsoleViewModel(snapshot);

  return (
    <ConsoleShell
      activeNav={activeNav}
      title={title}
      subtitle={subtitle}
      searchValue={query}
      searchPlaceholder={searchPlaceholder}
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: `${model.metrics.openIncidents} open incidents`, tone: model.metrics.openIncidents > 0 ? "warning" : "default" },
        { label: `${snapshot.devices.length} reporting devices` }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Readiness</p>
            <h3>{readinessTitle}</h3>
            <p className="muted-copy">{readinessCopy}</p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Current coverage</p>
            <ul className="key-list">
              <li>Incidents available for endpoint-originated detections.</li>
              <li>Devices and alerts are already correlating from the live control-plane snapshot.</li>
              <li>These pages are ready to absorb identity, mail, policy, and reporting connectors next.</li>
            </ul>
          </section>
        </div>
      }
    >
      <section className="grid grid-3">
        {integrationTargets.map((item) => (
          <article key={item.title} className="surface-card">
            <p className="section-kicker">Integration target</p>
            <h3>{item.title}</h3>
            <p className="muted-copy">{item.detail}</p>
          </article>
        ))}
      </section>

      <section className="grid grid-2">
        <article className="surface-card">
          <p className="section-kicker">Operational context</p>
          <h3>Why this page exists before the connector is live</h3>
          <p className="muted-copy">
            The console shell, navigation, search pattern, and analyst workflow are already in place, so new data
            sources can land into a stable user journey instead of creating one-off screens later.
          </p>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Backend path</p>
          <h3>What should feed this next</h3>
          <p className="muted-copy">
            Add dedicated backend entities and correlation logic for this domain, then bind the lists, detail views, and
            actions into the same incident-first operator workflow used by endpoints today.
          </p>
        </article>
      </section>
    </ConsoleShell>
  );
}
