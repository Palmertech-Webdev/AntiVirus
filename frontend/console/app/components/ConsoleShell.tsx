"use client";

import Link from "next/link";
import type { ReactNode } from "react";

import { BrandMark, NavGlyph } from "./BrandSystem";
import { getNavigationItems, type NavigationKey } from "../../lib/console-model";
import type { DataSource } from "../../lib/api";

interface StatusItem {
  label: string;
  tone?: "default" | "warning" | "danger";
}

interface ConsoleShellProps {
  activeNav: NavigationKey;
  title: string;
  subtitle: string;
  searchValue: string;
  searchPlaceholder: string;
  searchLabel?: string;
  onSearchChange: (nextValue: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  source: DataSource;
  generatedAt: string;
  policyRevision: string;
  statusItems?: StatusItem[];
  drawer?: ReactNode;
  children: ReactNode;
}

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function sourceLabel(source: DataSource) {
  return source === "live" ? "Live instance" : "Demo snapshot";
}

export default function ConsoleShell({
  activeNav,
  title,
  subtitle,
  searchValue,
  searchPlaceholder,
  searchLabel = "Global search",
  onSearchChange,
  onRefresh,
  refreshing,
  source,
  generatedAt,
  policyRevision,
  statusItems = [],
  drawer,
  children
}: ConsoleShellProps) {
  return (
    <div className="ops-shell">
      <aside className="ops-sidebar">
        <div className="brand-block">
          <div className="brand-header">
            <BrandMark className="brand-mark" />
            <div>
              <p className="brand-kicker">Enterprise AV</p>
              <h1>Operator Console</h1>
            </div>
          </div>
          <p className="brand-copy">Incident-led endpoint protection, response, and evidence management.</p>
        </div>

        <nav className="sidebar-nav">
          {getNavigationItems().map((item) => (
            <Link key={item.key} href={item.href} className={`sidebar-link ${activeNav === item.key ? "is-active" : ""}`}>
              <span className="nav-icon-shell">
                <NavGlyph name={item.icon} className="nav-icon" />
              </span>
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>

        <section className="sidebar-card">
          <p className="section-kicker">Platform state</p>
          <div className="sidebar-metadata">
            <div>
              <span className="meta-label">Mode</span>
              <strong>{sourceLabel(source)}</strong>
            </div>
            <div>
              <span className="meta-label">Generated</span>
              <strong>{formatDateTime(generatedAt)}</strong>
            </div>
            <div>
              <span className="meta-label">Policy</span>
              <strong>{policyRevision}</strong>
            </div>
          </div>
        </section>
      </aside>

      <div className="ops-main">
        <header className="topbar">
          <div className="page-copy">
            <p className="section-kicker">Operations</p>
            <h2>{title}</h2>
            <p>{subtitle}</p>
          </div>

          <div className="topbar-search">
            <label className="search-shell">
              <span className="meta-label">{searchLabel}</span>
              <input
                className="search-field"
                value={searchValue}
                onChange={(event) => {
                  onSearchChange(event.target.value);
                }}
                placeholder={searchPlaceholder}
              />
            </label>
          </div>

          <div className="topbar-actions">
            <span className={`source-pill source-${source}`}>{sourceLabel(source)}</span>
            {statusItems.map((item) => (
              <span key={item.label} className={`state-chip tone-${item.tone ?? "default"}`}>
                {item.label}
              </span>
            ))}
            <button type="button" className="refresh-button" onClick={onRefresh} disabled={refreshing}>
              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </header>

        <div className={`workspace ${drawer ? "with-drawer" : ""}`}>
          <div className="workspace-content">{children}</div>
          {drawer ? <aside className="context-drawer">{drawer}</aside> : null}
        </div>
      </div>
    </div>
  );
}
