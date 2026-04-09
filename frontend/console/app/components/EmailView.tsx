"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { useMailData } from "./useMailData";
import { buildConsoleViewModel, filterIncidents } from "../../lib/console-model";

function formatDateTime(value: string | null) {
  return value ? new Date(value).toLocaleString() : "Pending";
}

function toneClassName(value: string) {
  return `tone-${value}`;
}

function countTargetedUsers(recipients: string[]) {
  return new Set(recipients.map((item) => item.toLowerCase())).size;
}

export default function EmailView() {
  const { snapshot: consoleSnapshot, source: consoleSource, refreshSnapshot: refreshConsoleSnapshot } = useConsoleData();
  const {
    snapshot,
    source,
    loading,
    refreshing,
    mutating,
    refreshSnapshot,
    releaseQuarantine,
    purgeMessage
  } = useMailData();
  const [query, setQuery] = useState("");
  const [selectedMessageId, setSelectedMessageId] = useState<string | null>(null);

  const model = buildConsoleViewModel(consoleSnapshot);
  const filteredMessages = snapshot.recentMessages.filter((message) => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) {
      return true;
    }

    return [
      message.subject,
      message.sender,
      message.domain,
      message.verdict,
      message.deliveryAction,
      message.recipients.join(" "),
      message.summary,
      message.attachments.map((item) => item.fileName).join(" "),
      message.urls.map((item) => item.originalUrl).join(" ")
    ].some((value) => value.toLowerCase().includes(normalized));
  });

  const selectedMessage =
    filteredMessages.find((item) => item.id === selectedMessageId) ??
    snapshot.recentMessages.find((item) => item.id === selectedMessageId) ??
    filteredMessages[0] ??
    snapshot.recentMessages[0] ??
    null;
  const selectedQuarantine =
    selectedMessage ? snapshot.quarantineItems.find((item) => item.mailMessageId === selectedMessage.id) ?? null : null;
  const relatedIncident =
    selectedMessage
      ? model.incidents.find(
          (incident) =>
            (selectedMessage.relatedAlertId && incident.relatedAlertIds.includes(selectedMessage.relatedAlertId)) ||
            (selectedMessage.relatedDeviceId && incident.deviceIds.includes(selectedMessage.relatedDeviceId))
        ) ?? null
      : null;

  const linkedIncidents = filterIncidents(
    model.incidents.filter((incident) =>
      snapshot.recentMessages.some(
        (message) =>
          (message.relatedAlertId && incident.relatedAlertIds.includes(message.relatedAlertId)) ||
          (message.relatedDeviceId && incident.deviceIds.includes(message.relatedDeviceId))
      )
    ),
    query
  ).slice(0, 6);

  const quarantinedCount = snapshot.quarantineItems.filter((item) => item.status === "quarantined").length;
  const maliciousCount = snapshot.recentMessages.filter(
    (item) => item.verdict === "malware" || item.verdict === "phish"
  ).length;
  const targetedUsers = countTargetedUsers(snapshot.recentMessages.flatMap((item) => item.recipients));
  const actionsEnabled = source === "live";

  return (
    <ConsoleShell
      activeNav="email"
      title="Email"
      subtitle="Message trace, domain health, quarantine actions, and the first real mail investigation surface."
      searchValue={query}
      searchPlaceholder="Search subjects, senders, recipients, URLs, attachments, verdicts, or linked incidents..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void Promise.all([refreshSnapshot("manual"), refreshConsoleSnapshot("manual")]);
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: loading ? "loading mail snapshot" : `${snapshot.domains.length} mail domains`, tone: snapshot.domains.length > 0 ? "default" : "warning" },
        { label: `${quarantinedCount} quarantined messages`, tone: quarantinedCount > 0 ? "warning" : "default" },
        { label: `${consoleSource} incident correlation` }
      ]}
      drawer={
        selectedMessage ? (
          <div className="drawer-stack">
            <section className="drawer-panel">
              <div className="row-between">
                <p className="section-kicker">Selected message</p>
                <span className={`state-chip ${toneClassName(selectedMessage.verdict)}`}>{selectedMessage.verdict}</span>
              </div>
              <h3>{selectedMessage.subject}</h3>
              <p className="muted-copy">{selectedMessage.summary}</p>
              <dl className="definition-grid">
                <div>
                  <dt>Sender</dt>
                  <dd>{selectedMessage.sender}</dd>
                </div>
                <div>
                  <dt>Action</dt>
                  <dd>{selectedMessage.deliveryAction}</dd>
                </div>
                <div>
                  <dt>Recipients</dt>
                  <dd>{selectedMessage.recipients.join(", ")}</dd>
                </div>
                <div>
                  <dt>Received</dt>
                  <dd>{formatDateTime(selectedMessage.receivedAt)}</dd>
                </div>
              </dl>
            </section>

            <section className="drawer-panel">
              <p className="section-kicker">Authentication</p>
              <div className="tag-row">
                <span className={`state-chip ${toneClassName(selectedMessage.auth.spf)}`}>SPF {selectedMessage.auth.spf}</span>
                <span className={`state-chip ${toneClassName(selectedMessage.auth.dkim)}`}>DKIM {selectedMessage.auth.dkim}</span>
                <span className={`state-chip ${toneClassName(selectedMessage.auth.dmarc)}`}>DMARC {selectedMessage.auth.dmarc}</span>
                <span className={`state-chip ${toneClassName(selectedMessage.auth.arc)}`}>ARC {selectedMessage.auth.arc}</span>
              </div>
              {selectedMessage.attachments.length > 0 ? (
                <div className="surface-subsection">
                  <p className="section-kicker">Attachments</p>
                  {selectedMessage.attachments.map((attachment) => (
                    <div key={attachment.id} className="mini-card">
                      <strong>{attachment.fileName}</strong>
                      <p>{attachment.sizeBytes.toLocaleString()} bytes</p>
                      <code className="hash-line">{attachment.sha256}</code>
                    </div>
                  ))}
                </div>
              ) : null}
              {selectedMessage.urls.length > 0 ? (
                <div className="surface-subsection">
                  <p className="section-kicker">URLs</p>
                  {selectedMessage.urls.map((url) => (
                    <div key={url.id} className="mini-card">
                      <strong>{url.originalUrl}</strong>
                      <p>
                        {url.verdict} {url.rewriteApplied ? "· rewritten" : "· original"}
                      </p>
                    </div>
                  ))}
                </div>
              ) : null}
            </section>

            <section className="drawer-panel">
              <p className="section-kicker">Operator actions</p>
              <div className="action-stack">
                <button
                  type="button"
                  className="primary-link"
                  disabled={!actionsEnabled || mutating || !selectedQuarantine || selectedQuarantine.status !== "quarantined"}
                  onClick={() => {
                    if (selectedQuarantine) {
                      void releaseQuarantine(selectedQuarantine.id);
                    }
                  }}
                >
                  {mutating ? "Working..." : "Release message"}
                </button>
                <button
                  type="button"
                  className="secondary-link"
                  disabled={!actionsEnabled || mutating}
                  onClick={() => {
                    void purgeMessage(selectedMessage.id);
                  }}
                >
                  {mutating ? "Working..." : "Purge message"}
                </button>
                {relatedIncident ? (
                  <Link href={`/incidents/${relatedIncident.id}`} className="secondary-link">
                    Open incident
                  </Link>
                ) : null}
              </div>
              {!actionsEnabled ? (
                <p className="muted-copy">Mail actions are disabled while the console is using fallback data.</p>
              ) : null}
            </section>
          </div>
        ) : (
          <div className="drawer-panel">
            <p className="section-kicker">Selected message</p>
            <h3>No message selected</h3>
            <p className="muted-copy">Choose a message from the trace to review auth results, artifacts, and response actions.</p>
          </div>
        )
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Malicious or phishing mail</span>
          <strong className="metric-number">{maliciousCount}</strong>
          <p className="muted-copy">Messages currently classified as phishing or malware in the active trace window.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Quarantine queue</span>
          <strong className="metric-number">{quarantinedCount}</strong>
          <p className="muted-copy">Messages awaiting release, purge follow-up, or analyst validation.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Targeted users</span>
          <strong className="metric-number">{targetedUsers}</strong>
          <p className="muted-copy">Distinct recipients represented in the current message and quarantine sample.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Ready domains</span>
          <strong className="metric-number">{snapshot.domains.filter((item) => item.status === "ready").length}</strong>
          <p className="muted-copy">Domains that currently look healthy enough for MX-based pilot routing.</p>
        </article>
      </section>

      <section className="grid dashboard-main-grid">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Message trace</p>
              <h3>Recent mail flow</h3>
            </div>
          </div>

          <div className="table-shell">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>Message</th>
                  <th>Sender</th>
                  <th>Action</th>
                  <th>Recipients</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filteredMessages.map((message) => (
                  <tr
                    key={message.id}
                    className={selectedMessage?.id === message.id ? "is-selected" : ""}
                    onClick={() => {
                      setSelectedMessageId(message.id);
                    }}
                  >
                    <td>
                      <span className={`state-chip ${toneClassName(message.verdict)}`}>{message.verdict}</span>
                    </td>
                    <td>
                      <div className="table-primary">
                        <strong>{message.subject}</strong>
                        <span>{message.domain}</span>
                      </div>
                    </td>
                    <td>{message.sender}</td>
                    <td>
                      <span className={`state-chip ${toneClassName(message.deliveryAction)}`}>{message.deliveryAction}</span>
                    </td>
                    <td>{message.recipients.length}</td>
                    <td>{formatDateTime(message.receivedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredMessages.length === 0 ? <p className="empty-state">No messages match the current search.</p> : null}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Domain health</p>
              <h3>MX and downstream readiness</h3>
            </div>
          </div>

          <div className="mini-card-list">
            {snapshot.domains.map((domain) => (
              <article key={domain.id} className="mini-card">
                <div className="row-between">
                  <strong>{domain.domain}</strong>
                  <span className={`state-chip ${toneClassName(domain.status)}`}>{domain.status}</span>
                </div>
                <p>
                  {domain.mxRecordsConfigured ? "MX configured" : "MX pending"} · {domain.verificationStatus} · route{" "}
                  {domain.downstreamRoute}
                </p>
                <span className="mini-meta">
                  {domain.activeMessageCount} messages · {domain.quarantinedMessageCount} quarantined · last activity{" "}
                  {formatDateTime(domain.lastMessageAt)}
                </span>
              </article>
            ))}
          </div>

          <div className="surface-subsection">
            <p className="section-kicker">Mail policy</p>
            <dl className="definition-grid">
              <div>
                <dt>Default action</dt>
                <dd>{snapshot.defaultPolicy.defaultAction}</dd>
              </div>
              <div>
                <dt>Retention</dt>
                <dd>{snapshot.defaultPolicy.quarantineRetentionDays} days</dd>
              </div>
              <div>
                <dt>URL rewrite</dt>
                <dd>{snapshot.defaultPolicy.urlRewriteEnabled ? "Enabled" : "Disabled"}</dd>
              </div>
              <div>
                <dt>Impersonation</dt>
                <dd>{snapshot.defaultPolicy.impersonationProtectionEnabled ? "Enabled" : "Disabled"}</dd>
              </div>
            </dl>
          </div>
        </article>
      </section>

      <section className="grid dashboard-bottom-grid">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Quarantine</p>
              <h3>Messages awaiting operator attention</h3>
            </div>
          </div>

          <div className="row-card-list">
            {snapshot.quarantineItems.length === 0 ? (
              <p className="empty-state">No mail quarantine items are currently tracked.</p>
            ) : (
              snapshot.quarantineItems.map((item) => (
                <article key={item.id} className="row-card">
                  <div className="row-card-copy">
                    <p className="section-kicker">{item.domain}</p>
                    <h4>{item.subject}</h4>
                    <p className="muted-copy">{item.reason}</p>
                    <span className="mini-meta">
                      {item.sender} · {item.recipientSummary} · {formatDateTime(item.quarantinedAt)}
                    </span>
                  </div>
                  <div className="row-card-actions">
                    <span className={`state-chip ${toneClassName(item.status)}`}>{item.status}</span>
                    <button
                      type="button"
                      className="primary-link"
                      disabled={!actionsEnabled || mutating || item.status !== "quarantined"}
                      onClick={() => {
                        void releaseQuarantine(item.id);
                      }}
                    >
                      Release
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Cross-domain correlation</p>
              <h3>Linked incidents</h3>
            </div>
          </div>

          <div className="row-card-list">
            {linkedIncidents.length === 0 ? (
              <p className="empty-state">No linked incidents match the current mail view and search.</p>
            ) : (
              linkedIncidents.map((incident) => (
                <article key={incident.id} className="row-card">
                  <div className="row-card-copy">
                    <p className="section-kicker">{incident.sourceMix.join(" · ")}</p>
                    <h4>{incident.title}</h4>
                    <p className="muted-copy">{incident.summary}</p>
                    <span className="mini-meta">
                      {incident.deviceNames.join(", ")} · {formatDateTime(incident.lastActivityAt)}
                    </span>
                  </div>
                  <div className="row-card-actions">
                    <span className={`state-chip ${toneClassName(incident.severity)}`}>{incident.severity}</span>
                    <Link href={`/incidents/${incident.id}`} className="secondary-link">
                      Open incident
                    </Link>
                  </div>
                </article>
              ))
            )}
          </div>

          <div className="surface-subsection">
            <p className="section-kicker">Recent mail actions</p>
            <div className="mini-card-list">
              {snapshot.recentActions.length === 0 ? (
                <p className="empty-state">No mail actions have been recorded yet.</p>
              ) : (
                snapshot.recentActions.map((action) => (
                  <article key={action.id} className="mini-card">
                    <div className="row-between">
                      <strong>{action.actionType.replaceAll(".", " ")}</strong>
                      <span className={`state-chip ${toneClassName(action.status)}`}>{action.status}</span>
                    </div>
                    <p>{action.resultSummary}</p>
                    <span className="mini-meta">
                      {action.requestedBy} · {formatDateTime(action.requestedAt)}
                    </span>
                  </article>
                ))
              )}
            </div>
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
