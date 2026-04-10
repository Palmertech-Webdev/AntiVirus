"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import {
  apiBaseUrl,
  clearStoredAdminSessionToken,
  createAdminApiKey,
  createScript,
  getStoredAdminSessionToken,
  listAdminApiKeys,
  listAdminAuditEvents,
  listAdminSessions,
  loadAdminSession,
  loginAdmin,
  logoutAdmin,
  revokeAdminApiKey,
  updateScript
} from "../../lib/api";
import { buildConsoleViewModel } from "../../lib/console-model";
import type { AdminApiKeySummary, AdminAuditEventSummary, AdminSessionStateResponse } from "../../lib/types";

type AdminTabKey = "connectors" | "access" | "deployment" | "scripts" | "retention" | "api" | "audit";

const adminTabs: Array<{ key: AdminTabKey; label: string; description: string }> = [
  { key: "connectors", label: "Connectors", description: "Identity, mail, and external signal sources." },
  { key: "access", label: "Access", description: "SSO, MFA, RBAC, and operator sessions." },
  { key: "deployment", label: "Deployment", description: "Packages, rollout channels, and onboarding." },
  { key: "scripts", label: "Scripts", description: "Stored endpoint scripts for remote response and maintenance." },
  { key: "retention", label: "Retention", description: "Telemetry, evidence, quarantine, and audit windows." },
  { key: "api", label: "API Keys", description: "Programmatic access and scope control." },
  { key: "audit", label: "Audit", description: "Recent platform and operator activity." }
];

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function matchesQuery(query: string, values: Array<string | undefined | null>) {
  if (!query.trim()) {
    return true;
  }

  const normalized = query.trim().toLowerCase();
  return values.some((value) => value?.toLowerCase().includes(normalized));
}

function maskToken(seed: string) {
  return `avp_${seed.slice(0, 6)}...${seed.slice(-4)}`;
}

export default function AdministrationView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState<AdminTabKey>("connectors");
  const [lastAction, setLastAction] = useState("Administration now uses internal tabs. Save actions currently update the local UI draft.");
  const [adminSession, setAdminSession] = useState<AdminSessionStateResponse | null>(null);
  const [adminSessions, setAdminSessions] = useState<AdminSessionStateResponse["session"][]>([]);
  const [adminAuditEvents, setAdminAuditEvents] = useState<AdminAuditEventSummary[]>([]);
  const [adminApiKeys, setAdminApiKeys] = useState<AdminApiKeySummary[]>([]);
  const [adminLoginUsername, setAdminLoginUsername] = useState("admin@fenrir.local");
  const [adminLoginPassword, setAdminLoginPassword] = useState("");
  const [adminLoginMfaCode, setAdminLoginMfaCode] = useState("");
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [lastIssuedApiKeyToken, setLastIssuedApiKeyToken] = useState("");

  const [identityTenant, setIdentityTenant] = useState("");
  const [identityClientId, setIdentityClientId] = useState("");
  const [emailTenant, setEmailTenant] = useState("");
  const [emailClientId, setEmailClientId] = useState("");
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(true);
  const [sessionMinutes, setSessionMinutes] = useState(480);
  const [rolloutChannel, setRolloutChannel] = useState("stable");
  const [packageLabel, setPackageLabel] = useState("windows-x64-enterprise");
  const [selectedScriptId, setSelectedScriptId] = useState("");
  const [scriptName, setScriptName] = useState("");
  const [scriptDescription, setScriptDescription] = useState("");
  const [scriptLanguage, setScriptLanguage] = useState<"powershell" | "cmd">("powershell");
  const [scriptContent, setScriptContent] = useState("");
  const [telemetryDays, setTelemetryDays] = useState(30);
  const [evidenceDays, setEvidenceDays] = useState(90);
  const [newApiKeyName, setNewApiKeyName] = useState("");
  const [newApiKeyScopes, setNewApiKeyScopes] = useState("devices:read, incidents:read");

  const model = buildConsoleViewModel(snapshot);
  const selectedScript = snapshot.scripts.find((item) => item.id === selectedScriptId) ?? snapshot.scripts[0] ?? null;
  const versionCoverage = useMemo(() => {
    const counts = new Map<string, number>();
    for (const device of snapshot.devices) {
      const key = `${device.agentVersion} / ${device.platformVersion}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [snapshot.devices]);

  const auditFeed = useMemo(() => {
    const adminEvents = adminAuditEvents.map((item) => ({
      id: `admin-${item.id}`,
      title: item.action.replaceAll(".", " "),
      detail: `${item.actorName} · ${item.outcome}`,
      occurredAt: item.occurredAt
    }));
    const commandEvents = snapshot.recentCommands.map((item) => ({
      id: `command-${item.id}`,
      title: `${item.type.replaceAll(".", " ")} ${item.status.replaceAll("_", " ")}`,
      detail: `${item.hostname} · ${item.issuedBy}`,
      occurredAt: item.updatedAt
    }));
    const evidenceEvents = snapshot.recentEvidence.map((item) => ({
      id: `evidence-${item.recordId}`,
      title: `${item.disposition} evidence`,
      detail: `${item.hostname} · ${item.subjectPath}`,
      occurredAt: item.recordedAt
    }));

    return [...adminEvents, ...commandEvents, ...evidenceEvents]
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt))
      .filter((item) => matchesQuery(query, [item.title, item.detail]));
  }, [adminAuditEvents, query, snapshot.recentCommands, snapshot.recentEvidence]);

  const visibleTabs = adminTabs.filter((tab) => matchesQuery(query, [tab.label, tab.description]));
  const currentTab = visibleTabs.some((tab) => tab.key === activeTab) ? activeTab : (visibleTabs[0]?.key ?? "connectors");

  function loadScriptIntoEditor(scriptId: string) {
    const script = snapshot.scripts.find((item) => item.id === scriptId);
    setSelectedScriptId(scriptId);
    setScriptName(script?.name ?? "");
    setScriptDescription(script?.description ?? "");
    setScriptLanguage(script?.language ?? "powershell");
    setScriptContent(script?.content ?? "");
  }

  function saveDraft(message: string) {
    setLastAction(`${message} Backend persistence for administration settings is the next implementation step.`);
  }

  async function refreshAdminState() {
    if (!getStoredAdminSessionToken()) {
      setAdminSession(null);
      setAdminSessions([]);
      setAdminAuditEvents([]);
      setAdminApiKeys([]);
      return;
    }

    try {
      const [session, sessions, auditEvents, apiKeys] = await Promise.all([
        loadAdminSession(),
        listAdminSessions(),
        listAdminAuditEvents(50),
        listAdminApiKeys()
      ]);

      setAdminSession(session);
      setAdminSessions(sessions);
      setAdminAuditEvents(auditEvents);
      setAdminApiKeys(apiKeys);
    } catch {
      clearStoredAdminSessionToken();
      setAdminSession(null);
      setAdminSessions([]);
      setAdminAuditEvents([]);
      setAdminApiKeys([]);
      setLastIssuedApiKeyToken("");
    }
  }

  async function handleAdminLogin() {
    if (!adminLoginUsername.trim() || !adminLoginPassword.trim() || !adminLoginMfaCode.trim()) {
      setLastAction("Enter username, password, and MFA code to sign in.");
      return;
    }

    setAdminActionBusy(true);
    try {
      const session = await loginAdmin({
        username: adminLoginUsername.trim(),
        password: adminLoginPassword,
        mfaCode: adminLoginMfaCode.trim(),
        sessionMinutes
      });

      setAdminSession(session);
      setAdminLoginPassword("");
      setAdminLoginMfaCode("");
      await refreshAdminState();
      setLastAction(`Signed in as ${session.principal.displayName}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`Admin sign-in failed: ${message}`);
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function handleAdminLogout() {
    setAdminActionBusy(true);
    try {
      await logoutAdmin();
      clearStoredAdminSessionToken();
      setAdminSession(null);
      setAdminSessions([]);
      setAdminAuditEvents([]);
      setAdminApiKeys([]);
        setLastIssuedApiKeyToken("");
        setLastAction("Signed out of the admin console.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`Admin sign-out failed: ${message}`);
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function handleCreateApiKey() {
    if (!newApiKeyName.trim()) {
      setLastAction("Enter a key name before creating an API key.");
      return;
    }

    const scopes = newApiKeyScopes
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);

    if (scopes.length === 0) {
      setLastAction("Enter at least one scope before creating an API key.");
      return;
    }

    setAdminActionBusy(true);
    try {
      const created = await createAdminApiKey({
        name: newApiKeyName.trim(),
        scopes,
        sessionMinutes
      });

      setAdminApiKeys((current) => [created.apiKey, ...current.filter((item) => item.id !== created.apiKey.id)]);
      setNewApiKeyName("");
      setLastIssuedApiKeyToken(created.accessKey);
      setLastAction(`Created API key ${created.apiKey.name}. Token preview ${maskToken(created.accessKey)}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`API key creation failed: ${message}`);
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function handleRevokeApiKey(apiKeyId: string) {
    setAdminActionBusy(true);
    try {
      const revoked = await revokeAdminApiKey(apiKeyId);
      setAdminApiKeys((current) => current.map((item) => (item.id === revoked.id ? revoked : item)));
      setLastAction(`Revoked API key ${revoked.name}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`API key revocation failed: ${message}`);
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function saveScript() {
    try {
      if (!scriptName.trim() || !scriptContent.trim()) {
        setLastAction("Enter a script name and content before saving.");
        return;
      }

      if (selectedScriptId) {
        await updateScript(selectedScriptId, {
          name: scriptName.trim(),
          description: scriptDescription.trim() || undefined,
          language: scriptLanguage,
          content: scriptContent
        });
        setLastAction(`Updated stored script ${scriptName.trim()}.`);
      } else {
        const created = await createScript({
          name: scriptName.trim(),
          description: scriptDescription.trim() || undefined,
          language: scriptLanguage,
          content: scriptContent
        });
        setSelectedScriptId(created.id);
        setLastAction(`Created stored script ${created.name}.`);
      }

      await refreshSnapshot("manual");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`Script save failed: ${message}`);
    }
  }

  useEffect(() => {
    if (!getStoredAdminSessionToken()) {
      return;
    }

    void refreshAdminState().catch((error) => {
      const message = error instanceof Error ? error.message : "Request failed";
      setLastAction(`Admin session restore failed: ${message}`);
    });
  }, []);

  return (
    <ConsoleShell
      activeNav="administration"
      title="Administration"
      subtitle="Tenant settings, connectors, deployment posture, and operational configuration."
      searchValue={query}
      searchPlaceholder="Search admin tabs, settings, versions, audit, or connector text..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: source === "live" ? "live backend" : "demo fallback", tone: source === "live" ? "default" : "warning" },
        { label: `${snapshot.devices.length} reporting devices` }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Environment</p>
            <h3>{source === "live" ? "Live control plane connected" : "Console is using the demo fallback snapshot"}</h3>
            <p className="muted-copy">
              {source === "live"
                ? "This page now keeps setup inside Administration instead of bouncing you to other routes."
                : "The backend is offline, so the administration workspace is running against the offline demo snapshot."}
            </p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Selected tab</p>
            <h3>{adminTabs.find((tab) => tab.key === currentTab)?.label}</h3>
            <p className="muted-copy">{adminTabs.find((tab) => tab.key === currentTab)?.description}</p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Last action</p>
            <p className="muted-copy">{lastAction}</p>
          </section>
        </div>
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Mode</span>
          <strong className="metric-number">{source === "live" ? "Live" : "Demo"}</strong>
          <p className="muted-copy">Shows whether this workspace is backed by the live control plane or the offline fallback.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Connected sources</span>
          <strong className="metric-number">Endpoint</strong>
          <p className="muted-copy">Identity and mail setup now live inside the Connectors tab below.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Current incident load</span>
          <strong className="metric-number">{model.metrics.openIncidents}</strong>
          <p className="muted-copy">Useful context before changing policy, retention, or deployment settings.</p>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Administration workspace</p>
            <h3>Set the platform up here</h3>
          </div>
        </div>

        <div className="tab-strip" role="tablist" aria-label="Administration tabs">
          {visibleTabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              className={`tab-button ${currentTab === tab.key ? "is-active" : ""}`}
              onClick={() => {
                setActiveTab(tab.key);
              }}
            >
              <span>{tab.label}</span>
              <small>{tab.description}</small>
            </button>
          ))}
        </div>

        {currentTab === "connectors" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Identity connector</p>
              <h4>Microsoft Entra ID</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Tenant ID</span>
                  <input className="admin-input" value={identityTenant} onChange={(event) => setIdentityTenant(event.target.value)} placeholder="Tenant ID" />
                </label>
                <label className="field-group">
                  <span>Client ID</span>
                  <input className="admin-input" value={identityClientId} onChange={(event) => setIdentityClientId(event.target.value)} placeholder="Client ID" />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => saveDraft("Saved Entra ID connector draft.")}>Save connector</button>
                <button type="button" className="secondary-link" onClick={() => saveDraft("Queued Entra ID connector test.")}>Test connection</button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Email connector</p>
              <h4>Microsoft 365 mail telemetry</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Tenant ID</span>
                  <input className="admin-input" value={emailTenant} onChange={(event) => setEmailTenant(event.target.value)} placeholder="Mail tenant ID" />
                </label>
                <label className="field-group">
                  <span>Client ID</span>
                  <input className="admin-input" value={emailClientId} onChange={(event) => setEmailClientId(event.target.value)} placeholder="Graph client ID" />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => saveDraft("Saved Microsoft 365 mail connector draft.")}>Save connector</button>
                <button type="button" className="secondary-link" onClick={() => saveDraft("Queued mail connector test.")}>Test connection</button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">External forwarding</p>
              <h4>API target and webhook posture</h4>
              <p className="muted-copy">{apiBaseUrl}</p>
              <div className="form-actions">
                <button type="button" className="secondary-link" onClick={() => saveDraft("Saved webhook forwarding draft.")}>Save forwarding</button>
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "access" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Access controls</p>
              <h4>Authentication and sessions</h4>
              {adminSession ? (
                <div className="list-stack">
                  <article className="mini-card">
                    <div className="row-between">
                      <strong>{adminSession.principal.displayName}</strong>
                      <span className="state-chip tone-default">{adminSession.principal.roles.join(", ")}</span>
                    </div>
                    <p>{adminSession.principal.username}</p>
                    <span className="mini-meta">Session expires {formatDateTime(adminSession.session.expiresAt)}</span>
                    <span className="mini-meta">{adminSessions.filter((item) => !item.revokedAt).length} active session(s) in state</span>
                  </article>
                  <div className="field-grid">
                    <label className="field-group inline-toggle"><span>Enable SSO</span><input type="checkbox" checked={ssoEnabled} onChange={(event) => setSsoEnabled(event.target.checked)} /></label>
                    <label className="field-group inline-toggle"><span>Require MFA</span><input type="checkbox" checked={mfaRequired} onChange={(event) => setMfaRequired(event.target.checked)} /></label>
                    <label className="field-group">
                      <span>Session minutes</span>
                      <input className="admin-input" type="number" min={30} value={sessionMinutes} onChange={(event) => setSessionMinutes(Number(event.target.value) || 30)} />
                    </label>
                  </div>
                </div>
              ) : (
                <div className="field-grid">
                  <label className="field-group">
                    <span>Username</span>
                    <input className="admin-input" value={adminLoginUsername} onChange={(event) => setAdminLoginUsername(event.target.value)} placeholder="admin@fenrir.local" />
                  </label>
                  <label className="field-group">
                    <span>Password</span>
                    <input className="admin-input" type="password" value={adminLoginPassword} onChange={(event) => setAdminLoginPassword(event.target.value)} placeholder="Bootstrap password" />
                  </label>
                  <label className="field-group">
                    <span>MFA code</span>
                    <input className="admin-input" inputMode="numeric" value={adminLoginMfaCode} onChange={(event) => setAdminLoginMfaCode(event.target.value)} placeholder="123456" />
                  </label>
                  <label className="field-group">
                    <span>Session minutes</span>
                    <input className="admin-input" type="number" min={30} value={sessionMinutes} onChange={(event) => setSessionMinutes(Number(event.target.value) || 30)} />
                  </label>
                </div>
              )}
              <div className="form-actions">
                {adminSession ? (
                  <button type="button" className="primary-link" onClick={() => void handleAdminLogout()} disabled={adminActionBusy}>
                    Sign out
                  </button>
                ) : (
                  <button type="button" className="primary-link" onClick={() => void handleAdminLogin()} disabled={adminActionBusy}>
                    Sign in
                  </button>
                )}
                <button type="button" className="secondary-link" onClick={() => saveDraft("Saved access control draft.")}>Save access</button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Roles</p>
              <h4>Built-in operator roles</h4>
              <div className="list-stack">
                <article className="mini-card"><strong>Security analyst</strong><p>Investigates incidents, alerts, devices, and evidence.</p></article>
                <article className="mini-card"><strong>Platform administrator</strong><p>Manages connectors, retention, deployment, and API keys.</p></article>
                <article className="mini-card"><strong>Read-only auditor</strong><p>Reviews incidents, reports, and audit activity without changing settings.</p></article>
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "deployment" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Rollout settings</p>
              <h4>Onboarding and packages</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Rollout channel</span>
                  <input className="admin-input" value={rolloutChannel} onChange={(event) => setRolloutChannel(event.target.value)} />
                </label>
                <label className="field-group">
                  <span>Package label</span>
                  <input className="admin-input" value={packageLabel} onChange={(event) => setPackageLabel(event.target.value)} />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => saveDraft("Saved deployment draft.")}>Save deployment</button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Current rollout</p>
              <h4>Agent and platform coverage</h4>
              <div className="list-stack">
                {versionCoverage.length === 0 ? <p className="empty-state">No devices are currently reporting version coverage.</p> : versionCoverage.map(([label, count]) => (
                  <article key={label} className="mini-card">
                    <div className="row-between"><strong>{label}</strong><span className="state-chip tone-default">{count}</span></div>
                    <p>Devices currently reporting this agent/platform combination.</p>
                  </article>
                ))}
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "scripts" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Stored scripts</p>
              <h4>Reusable endpoint automation</h4>
              <div className="list-stack">
                {snapshot.scripts.filter((item) => matchesQuery(query, [item.name, item.description, item.language, item.content])).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`tab-button ${selectedScript?.id === item.id ? "is-active" : ""}`}
                    onClick={() => loadScriptIntoEditor(item.id)}
                  >
                    <span>{item.name}</span>
                    <small>
                      {item.language} · last executed {item.lastExecutedAt ? formatDateTime(item.lastExecutedAt) : "never"}
                    </small>
                  </button>
                ))}
                {snapshot.scripts.length === 0 ? <p className="empty-state">No stored scripts yet.</p> : null}
              </div>
              <div className="form-actions">
                <button
                  type="button"
                  className="secondary-link"
                  onClick={() => {
                    setSelectedScriptId("");
                    setScriptName("");
                    setScriptDescription("");
                    setScriptLanguage("powershell");
                    setScriptContent("");
                  }}
                >
                  New script
                </button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Script editor</p>
              <h4>{selectedScriptId ? "Update stored script" : "Create stored script"}</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Name</span>
                  <input className="admin-input" value={scriptName} onChange={(event) => setScriptName(event.target.value)} />
                </label>
                <label className="field-group">
                  <span>Language</span>
                  <select
                    className="admin-input"
                    value={scriptLanguage}
                    onChange={(event) => setScriptLanguage(event.target.value === "cmd" ? "cmd" : "powershell")}
                  >
                    <option value="powershell">PowerShell</option>
                    <option value="cmd">CMD</option>
                  </select>
                </label>
                <label className="field-group field-span-2">
                  <span>Description</span>
                  <input
                    className="admin-input"
                    value={scriptDescription}
                    onChange={(event) => setScriptDescription(event.target.value)}
                  />
                </label>
                <label className="field-group field-span-2">
                  <span>Content</span>
                  <textarea
                    className="admin-input"
                    rows={10}
                    value={scriptContent}
                    onChange={(event) => setScriptContent(event.target.value)}
                    placeholder="Write the remote script content here."
                  />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => void saveScript()}>
                  {selectedScriptId ? "Save script" : "Create script"}
                </button>
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "retention" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Retention controls</p>
              <h4>Data lifecycle settings</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Telemetry days</span>
                  <input className="admin-input" type="number" min={1} value={telemetryDays} onChange={(event) => setTelemetryDays(Number(event.target.value) || 1)} />
                </label>
                <label className="field-group">
                  <span>Evidence days</span>
                  <input className="admin-input" type="number" min={1} value={evidenceDays} onChange={(event) => setEvidenceDays(Number(event.target.value) || 1)} />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => saveDraft("Saved retention draft.")}>Save retention</button>
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Current object counts</p>
              <h4>Snapshot impact</h4>
              <div className="list-stack">
                <article className="mini-card"><strong>Telemetry</strong><p>{snapshot.recentTelemetry.length} recent records in the current snapshot.</p></article>
                <article className="mini-card"><strong>Evidence</strong><p>{snapshot.recentEvidence.length} evidence items currently visible.</p></article>
                <article className="mini-card"><strong>Quarantine</strong><p>{snapshot.quarantineItems.length} quarantine items currently represented.</p></article>
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "api" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Generate API key</p>
              <h4>Programmatic access</h4>
              <div className="field-grid">
                <label className="field-group">
                  <span>Key name</span>
                  <input className="admin-input" value={newApiKeyName} onChange={(event) => setNewApiKeyName(event.target.value)} placeholder="automation-name" />
                </label>
                <label className="field-group field-span-2">
                  <span>Scopes</span>
                  <input className="admin-input" value={newApiKeyScopes} onChange={(event) => setNewApiKeyScopes(event.target.value)} placeholder="devices:read, incidents:read" />
                </label>
              </div>
              <div className="form-actions">
                <button type="button" className="primary-link" onClick={() => void handleCreateApiKey()} disabled={adminActionBusy || !adminSession}>
                  Generate key
                </button>
              </div>
              {lastIssuedApiKeyToken ? <code className="hash-line">{lastIssuedApiKeyToken}</code> : null}
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Issued keys</p>
              <h4>Current tokens</h4>
              <div className="list-stack">
                {adminApiKeys.filter((item) => matchesQuery(query, [item.name, item.scopes.join(", "), item.principalUsername])).map((item) => (
                  <article key={item.id} className="mini-card">
                    <div className="row-between">
                      <strong>{item.name}</strong>
                      <span className={`state-chip ${item.revokedAt ? "tone-warning" : "tone-default"}`}>{item.revokedAt ? "revoked" : "active"}</span>
                    </div>
                    <p>{item.principalUsername} · {item.scopes.join(", ")}</p>
                    <span className="mini-meta">Created {formatDateTime(item.createdAt)}</span>
                    <span className="mini-meta">{item.lastUsedAt ? `Last used ${formatDateTime(item.lastUsedAt)}` : "Never used"}</span>
                    {!item.revokedAt ? (
                      <div className="form-actions">
                        <button type="button" className="secondary-link" onClick={() => void handleRevokeApiKey(item.id)} disabled={adminActionBusy}>
                          Revoke
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))}
                {adminApiKeys.length === 0 ? <p className="empty-state">No API keys have been issued yet.</p> : null}
              </div>
            </article>
          </div>
        ) : null}

        {currentTab === "audit" ? (
          <div className="admin-panel-grid">
            <article className="surface-card inset-card">
              <p className="section-kicker">Recent platform activity</p>
              <h4>Audit-style feed</h4>
              <div className="list-stack">
                {auditFeed.length === 0 ? <p className="empty-state">No audit-like activity matches the current search.</p> : auditFeed.map((item) => (
                  <article key={item.id} className="mini-card">
                    <div className="row-between"><strong>{item.title}</strong><span className="state-chip tone-default">{formatDateTime(item.occurredAt)}</span></div>
                    <p>{item.detail}</p>
                  </article>
                ))}
              </div>
            </article>

            <article className="surface-card inset-card">
              <p className="section-kicker">Operator links</p>
              <h4>Jump to live work surfaces</h4>
              <div className="row-card-list">
                <article className="row-card">
                  <div className="row-card-copy"><p className="section-kicker">Incident operations</p><h4>Review what needs action now</h4></div>
                  <div className="row-card-actions"><Link href="/incidents" className="primary-link">Open incidents</Link></div>
                </article>
                <article className="row-card">
                  <div className="row-card-copy"><p className="section-kicker">Endpoint inventory</p><h4>Review device posture and containment state</h4></div>
                  <div className="row-card-actions"><Link href="/devices" className="primary-link">Open devices</Link></div>
                </article>
              </div>
            </article>
          </div>
        ) : null}
      </section>
    </ConsoleShell>
  );
}
