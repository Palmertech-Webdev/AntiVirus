"use client";

import { useEffect, useMemo, useState } from "react";

import ConsoleShell from "./ConsoleShell";
import {
  assignPolicy,
  createPolicy,
  createPolicyExclusionChangeRequest,
  listPolicyExclusionChangeRequests,
  reviewPolicyExclusionChangeRequest,
  updatePolicy
} from "../../lib/api";
import { useConsoleData } from "./useConsoleData";
import { filterDevices } from "../../lib/console-model";
import type {
  PolicyExclusionChangeEntry,
  PolicyExclusionChangeRequestSummary,
  PolicyExclusionListType
} from "../../lib/types";

function formatBoolean(value: boolean) {
  return value ? "Enabled" : "Disabled";
}

function formatPolicyList(values: string[]) {
  return values.join("\n");
}

function parsePolicyList(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function buildExclusionChangeEntries(
  listType: PolicyExclusionListType,
  currentValues: string[],
  proposedValues: string[]
): PolicyExclusionChangeEntry[] {
  const normalize = (value: string) => (listType === "sha256" ? value.trim().toLowerCase() : value.trim());
  const currentSet = new Set(currentValues.map((item) => normalize(item)).filter((item) => item.length > 0));
  const proposedSet = new Set(proposedValues.map((item) => normalize(item)).filter((item) => item.length > 0));
  const entries: PolicyExclusionChangeEntry[] = [];

  for (const value of proposedSet) {
    if (!currentSet.has(value)) {
      entries.push({ listType, operation: "add", value });
    }
  }

  for (const value of currentSet) {
    if (!proposedSet.has(value)) {
      entries.push({ listType, operation: "remove", value });
    }
  }

  return entries;
}

function formatExclusionListType(listType: PolicyExclusionListType) {
  if (listType === "path_root") {
    return "Path root";
  }

  if (listType === "sha256") {
    return "SHA-256";
  }

  return "Signer name";
}

export default function PoliciesView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [selectedPolicyId, setSelectedPolicyId] = useState("");
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const [newPolicyName, setNewPolicyName] = useState("");
  const [newPolicyDescription, setNewPolicyDescription] = useState("");
  const [newRealtimeProtection, setNewRealtimeProtection] = useState(true);
  const [newCloudLookup, setNewCloudLookup] = useState(true);
  const [newScriptInspection, setNewScriptInspection] = useState(true);
  const [newNetworkContainment, setNewNetworkContainment] = useState(true);
  const [newQuarantineOnMalicious, setNewQuarantineOnMalicious] = useState(true);
  const [newSuppressionPathRoots, setNewSuppressionPathRoots] = useState("");
  const [newSuppressionSha256, setNewSuppressionSha256] = useState("");
  const [newSuppressionSignerNames, setNewSuppressionSignerNames] = useState("");

  const policies = snapshot.policies;
  const currentPolicy = policies.find((item) => item.id === selectedPolicyId) ?? policies[0] ?? null;
  const assignedDevices = filterDevices(snapshot.devices, query);

  const [policyName, setPolicyName] = useState("");
  const [policyDescription, setPolicyDescription] = useState("");
  const [policyRealtimeProtection, setPolicyRealtimeProtection] = useState(true);
  const [policyCloudLookup, setPolicyCloudLookup] = useState(true);
  const [policyScriptInspection, setPolicyScriptInspection] = useState(true);
  const [policyNetworkContainment, setPolicyNetworkContainment] = useState(true);
  const [policyQuarantineOnMalicious, setPolicyQuarantineOnMalicious] = useState(true);
  const [policySuppressionPathRoots, setPolicySuppressionPathRoots] = useState("");
  const [policySuppressionSha256, setPolicySuppressionSha256] = useState("");
  const [policySuppressionSignerNames, setPolicySuppressionSignerNames] = useState("");
  const [policyExclusionRequests, setPolicyExclusionRequests] = useState<PolicyExclusionChangeRequestSummary[]>([]);
  const [policyExclusionReason, setPolicyExclusionReason] = useState("");
  const [policyExclusionReviewComment, setPolicyExclusionReviewComment] = useState("");

  async function refreshPolicyExclusionRequests(policyId: string) {
    const items = await listPolicyExclusionChangeRequests({ policyId, limit: 50 });
    setPolicyExclusionRequests(items);
  }

  useEffect(() => {
    if (!selectedPolicyId && policies[0]) {
      setSelectedPolicyId(policies[0].id);
    }
  }, [policies, selectedPolicyId]);

  useEffect(() => {
    if (!currentPolicy) {
      return;
    }

    setPolicyName(currentPolicy.name);
    setPolicyDescription(currentPolicy.description);
    setPolicyRealtimeProtection(currentPolicy.realtimeProtection);
    setPolicyCloudLookup(currentPolicy.cloudLookup);
    setPolicyScriptInspection(currentPolicy.scriptInspection);
    setPolicyNetworkContainment(currentPolicy.networkContainment);
    setPolicyQuarantineOnMalicious(currentPolicy.quarantineOnMalicious);
    setPolicySuppressionPathRoots(formatPolicyList(currentPolicy.suppressionPathRoots));
    setPolicySuppressionSha256(formatPolicyList(currentPolicy.suppressionSha256));
    setPolicySuppressionSignerNames(formatPolicyList(currentPolicy.suppressionSignerNames));
    setSelectedDeviceIds(currentPolicy.assignedDeviceIds);
  }, [currentPolicy]);

  useEffect(() => {
    if (!currentPolicy) {
      setPolicyExclusionRequests([]);
      return;
    }

    let cancelled = false;
    void listPolicyExclusionChangeRequests({ policyId: currentPolicy.id, limit: 50 })
      .then((items) => {
        if (!cancelled) {
          setPolicyExclusionRequests(items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPolicyExclusionRequests([]);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [currentPolicy?.id]);

  const protectedDevices = useMemo(
    () => assignedDevices.filter((device) => device.policyName === snapshot.defaultPolicy.name).length,
    [assignedDevices, snapshot.defaultPolicy.name]
  );

  async function runPolicyAction(label: string, action: () => Promise<void>) {
    setActionBusy(label);
    setActionMessage(null);

    try {
      await action();
      setActionMessage(`${label} completed.`);
      await refreshSnapshot("manual");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed";
      setActionMessage(`${label} failed: ${message}`);
    } finally {
      setActionBusy(null);
    }
  }

  return (
    <ConsoleShell
      activeNav="policies"
      title="Policies"
      subtitle="Create, amend, and assign protection profiles to devices."
      searchValue={query}
      searchPlaceholder="Search policies, revisions, device assignments, protections, or exclusions..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: snapshot.defaultPolicy.name },
        { label: `${protectedDevices} default-policy devices`, tone: "default" }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Active policy</p>
            <h3>{currentPolicy?.name ?? "No policy selected"}</h3>
            <p className="muted-copy">Revision {currentPolicy?.revision ?? "pending"}</p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Assignment summary</p>
            <h3>{currentPolicy?.assignedDeviceIds.length ?? 0} devices</h3>
            <p className="muted-copy">Policy assignments are now live and written back to the backend.</p>
          </section>
          {actionMessage ? (
            <section className="drawer-panel">
              <p className="section-kicker">Last action</p>
              <p className="muted-copy">{actionMessage}</p>
            </section>
          ) : null}
        </div>
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Realtime protection</span>
          <strong className="metric-number">{formatBoolean(snapshot.defaultPolicy.realtimeProtection)}</strong>
          <p className="muted-copy">Kernel and user-mode protection paths expected under the current baseline.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Script inspection</span>
          <strong className="metric-number">{formatBoolean(snapshot.defaultPolicy.scriptInspection)}</strong>
          <p className="muted-copy">AMSI-backed script inspection in the current default policy.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Policy count</span>
          <strong className="metric-number">{policies.length}</strong>
          <p className="muted-copy">Profiles now persisted in the backend instead of being a single static baseline.</p>
        </article>
      </section>

      {actionMessage ? (
        <section className="surface-card">
          <p className="section-kicker">Policy action status</p>
          <h3>{actionMessage}</h3>
        </section>
      ) : null}

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Create policy</p>
              <h3>Add a new protection profile</h3>
            </div>
          </div>
          <div className="field-grid">
            <label className="field-group">
              <span>Name</span>
              <input className="admin-input" value={newPolicyName} onChange={(event) => setNewPolicyName(event.target.value)} />
            </label>
            <label className="field-group field-span-2">
              <span>Description</span>
              <input
                className="admin-input"
                value={newPolicyDescription}
                onChange={(event) => setNewPolicyDescription(event.target.value)}
              />
            </label>
            <label className="field-group inline-toggle"><span>Realtime protection</span><input type="checkbox" checked={newRealtimeProtection} onChange={(event) => setNewRealtimeProtection(event.target.checked)} /></label>
            <label className="field-group inline-toggle"><span>Cloud lookup</span><input type="checkbox" checked={newCloudLookup} onChange={(event) => setNewCloudLookup(event.target.checked)} /></label>
            <label className="field-group inline-toggle"><span>Script inspection</span><input type="checkbox" checked={newScriptInspection} onChange={(event) => setNewScriptInspection(event.target.checked)} /></label>
            <label className="field-group inline-toggle"><span>Network containment</span><input type="checkbox" checked={newNetworkContainment} onChange={(event) => setNewNetworkContainment(event.target.checked)} /></label>
            <label className="field-group inline-toggle"><span>Quarantine on malicious</span><input type="checkbox" checked={newQuarantineOnMalicious} onChange={(event) => setNewQuarantineOnMalicious(event.target.checked)} /></label>
            <label className="field-group field-span-2">
              <span>Suppressed path roots</span>
              <textarea
                className="admin-input"
                rows={4}
                placeholder={"C:\\Program Files\\Trusted App\nC:\\Tools\\KnownClean"}
                value={newSuppressionPathRoots}
                onChange={(event) => setNewSuppressionPathRoots(event.target.value)}
              />
            </label>
            <label className="field-group">
              <span>Suppressed SHA-256</span>
              <textarea
                className="admin-input"
                rows={4}
                placeholder={"ab12...\ncd34..."}
                value={newSuppressionSha256}
                onChange={(event) => setNewSuppressionSha256(event.target.value)}
              />
            </label>
            <label className="field-group">
              <span>Suppressed signer names</span>
              <textarea
                className="admin-input"
                rows={4}
                placeholder={"Microsoft Windows\nAdobe Inc."}
                value={newSuppressionSignerNames}
                onChange={(event) => setNewSuppressionSignerNames(event.target.value)}
              />
            </label>
          </div>
          <div className="form-actions">
            <button
              type="button"
              className="primary-link"
              disabled={Boolean(actionBusy) || !newPolicyName.trim()}
              onClick={() => {
                void runPolicyAction("Create policy", async () => {
                  const createdPolicy = await createPolicy({
                    name: newPolicyName.trim(),
                    description: newPolicyDescription.trim() || undefined,
                    realtimeProtection: newRealtimeProtection,
                    cloudLookup: newCloudLookup,
                    scriptInspection: newScriptInspection,
                    networkContainment: newNetworkContainment,
                    quarantineOnMalicious: newQuarantineOnMalicious
                  });

                  const initialExclusionEntries = [
                    ...buildExclusionChangeEntries("path_root", [], parsePolicyList(newSuppressionPathRoots)),
                    ...buildExclusionChangeEntries("sha256", [], parsePolicyList(newSuppressionSha256)),
                    ...buildExclusionChangeEntries("signer_name", [], parsePolicyList(newSuppressionSignerNames))
                  ];
                  if (initialExclusionEntries.length > 0) {
                    await createPolicyExclusionChangeRequest(createdPolicy.id, {
                      reason: "Initial suppression entries requested during policy creation.",
                      entries: initialExclusionEntries
                    });
                  }

                  setNewPolicyName("");
                  setNewPolicyDescription("");
                  setNewSuppressionPathRoots("");
                  setNewSuppressionSha256("");
                  setNewSuppressionSignerNames("");
                });
              }}
            >
              Create policy
            </button>
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Policy library</p>
              <h3>Select a profile to amend</h3>
            </div>
          </div>
          <div className="tab-strip" role="tablist" aria-label="Policies">
            {policies.map((policy) => (
              <button
                key={policy.id}
                type="button"
                className={`tab-button ${currentPolicy?.id === policy.id ? "is-active" : ""}`}
                onClick={() => setSelectedPolicyId(policy.id)}
              >
                <span>{policy.name}</span>
                <small>{policy.revision}</small>
              </button>
            ))}
          </div>
        </article>
      </section>

      {currentPolicy ? (
        <section className="grid grid-2">
          <article className="surface-card">
            <div className="section-heading">
              <div>
                <p className="section-kicker">Edit policy</p>
                <h3>{currentPolicy.name}</h3>
              </div>
            </div>
            <div className="field-grid">
              <label className="field-group">
                <span>Name</span>
                <input className="admin-input" value={policyName} onChange={(event) => setPolicyName(event.target.value)} />
              </label>
              <label className="field-group field-span-2">
                <span>Description</span>
                <input className="admin-input" value={policyDescription} onChange={(event) => setPolicyDescription(event.target.value)} />
              </label>
              <label className="field-group inline-toggle"><span>Realtime protection</span><input type="checkbox" checked={policyRealtimeProtection} onChange={(event) => setPolicyRealtimeProtection(event.target.checked)} /></label>
              <label className="field-group inline-toggle"><span>Cloud lookup</span><input type="checkbox" checked={policyCloudLookup} onChange={(event) => setPolicyCloudLookup(event.target.checked)} /></label>
              <label className="field-group inline-toggle"><span>Script inspection</span><input type="checkbox" checked={policyScriptInspection} onChange={(event) => setPolicyScriptInspection(event.target.checked)} /></label>
              <label className="field-group inline-toggle"><span>Network containment</span><input type="checkbox" checked={policyNetworkContainment} onChange={(event) => setPolicyNetworkContainment(event.target.checked)} /></label>
              <label className="field-group inline-toggle"><span>Quarantine on malicious</span><input type="checkbox" checked={policyQuarantineOnMalicious} onChange={(event) => setPolicyQuarantineOnMalicious(event.target.checked)} /></label>
              <label className="field-group field-span-2">
                <span>Suppressed path roots</span>
                <textarea
                  className="admin-input"
                  rows={4}
                  placeholder={"C:\\Program Files\\Trusted App\nC:\\Tools\\KnownClean"}
                  value={policySuppressionPathRoots}
                  onChange={(event) => setPolicySuppressionPathRoots(event.target.value)}
                />
              </label>
              <label className="field-group">
                <span>Suppressed SHA-256</span>
                <textarea
                  className="admin-input"
                  rows={4}
                  placeholder={"ab12...\ncd34..."}
                  value={policySuppressionSha256}
                  onChange={(event) => setPolicySuppressionSha256(event.target.value)}
                />
              </label>
              <label className="field-group">
                <span>Suppressed signer names</span>
                <textarea
                  className="admin-input"
                  rows={4}
                  placeholder={"Microsoft Windows\nAdobe Inc."}
                  value={policySuppressionSignerNames}
                  onChange={(event) => setPolicySuppressionSignerNames(event.target.value)}
                />
              </label>
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="primary-link"
                disabled={Boolean(actionBusy) || !policyName.trim()}
                onClick={() => {
                  void runPolicyAction("Save policy", async () => {
                    await updatePolicy(currentPolicy.id, {
                      name: policyName.trim(),
                      description: policyDescription.trim() || undefined,
                      realtimeProtection: policyRealtimeProtection,
                      cloudLookup: policyCloudLookup,
                      scriptInspection: policyScriptInspection,
                      networkContainment: policyNetworkContainment,
                      quarantineOnMalicious: policyQuarantineOnMalicious
                    });
                  });
                }}
              >
                Save policy
              </button>
              <button
                type="button"
                className="primary-link"
                disabled={Boolean(actionBusy) || !policyExclusionReason.trim()}
                onClick={() => {
                  void runPolicyAction("Submit exclusion request", async () => {
                    const exclusionEntries = [
                      ...buildExclusionChangeEntries(
                        "path_root",
                        currentPolicy.suppressionPathRoots,
                        parsePolicyList(policySuppressionPathRoots)
                      ),
                      ...buildExclusionChangeEntries(
                        "sha256",
                        currentPolicy.suppressionSha256,
                        parsePolicyList(policySuppressionSha256)
                      ),
                      ...buildExclusionChangeEntries(
                        "signer_name",
                        currentPolicy.suppressionSignerNames,
                        parsePolicyList(policySuppressionSignerNames)
                      )
                    ];

                    if (exclusionEntries.length === 0) {
                      setActionMessage("Submit exclusion request skipped: no suppression changes were detected.");
                      return;
                    }

                    await createPolicyExclusionChangeRequest(currentPolicy.id, {
                      reason: policyExclusionReason.trim(),
                      entries: exclusionEntries
                    });

                    setPolicyExclusionReason("");
                    await refreshPolicyExclusionRequests(currentPolicy.id);
                  });
                }}
              >
                Submit exclusion request
              </button>
            </div>
            <label className="field-group field-span-2">
              <span>Exclusion request reason</span>
              <input
                className="admin-input"
                value={policyExclusionReason}
                onChange={(event) => setPolicyExclusionReason(event.target.value)}
                placeholder="Describe why this exclusion is required and what validation was performed."
              />
            </label>
          </article>

          <article className="surface-card">
            <div className="section-heading">
              <div>
                <p className="section-kicker">Assignments</p>
                <h3>Assign {currentPolicy.name} to devices</h3>
              </div>
            </div>
            <div className="list-stack">
              {assignedDevices.map((device) => (
                <label key={device.id} className="mini-card">
                  <div className="row-between">
                    <strong>{device.hostname}</strong>
                    <input
                      type="checkbox"
                      checked={selectedDeviceIds.includes(device.id)}
                      onChange={(event) => {
                        setSelectedDeviceIds((current) =>
                          event.target.checked
                            ? [...new Set([...current, device.id])]
                            : current.filter((item) => item !== device.id)
                        );
                      }}
                    />
                  </div>
                  <p>{device.policyName}</p>
                  <span className="mini-meta">
                    {device.healthState} · {device.postureState} · {device.osVersion}
                  </span>
                </label>
              ))}
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="primary-link"
                disabled={Boolean(actionBusy) || selectedDeviceIds.length === 0}
                onClick={() => {
                  void runPolicyAction("Assign policy", async () => {
                    await assignPolicy(currentPolicy.id, { deviceIds: selectedDeviceIds });
                  });
                }}
              >
                Assign to selected devices
              </button>
            </div>
            <div className="section-heading">
              <div>
                <p className="section-kicker">Exclusion workflow</p>
                <h3>Request and review suppression changes</h3>
              </div>
            </div>
            <label className="field-group">
              <span>Review comment</span>
              <input
                className="admin-input"
                value={policyExclusionReviewComment}
                onChange={(event) => setPolicyExclusionReviewComment(event.target.value)}
                placeholder="Optional approval or rejection notes for the audit trail."
              />
            </label>
            <div className="list-stack">
              {policyExclusionRequests.length === 0 ? (
                <p className="muted-copy">No exclusion requests are recorded for this policy yet.</p>
              ) : (
                policyExclusionRequests.map((request) => (
                  <article key={request.id} className="mini-card">
                    <div className="row-between">
                      <strong>{request.id.slice(0, 8)}</strong>
                      <span className="mini-meta">{request.status}</span>
                    </div>
                    <p>{request.reason}</p>
                    <span className="mini-meta">
                      {request.requestedBy} · {new Date(request.requestedAt).toLocaleString()}
                    </span>
                    <span className="mini-meta">
                      {request.entries
                        .map((entry) => `${entry.operation} ${formatExclusionListType(entry.listType)}: ${entry.value}`)
                        .join("; ")}
                    </span>
                    {request.status === "pending" ? (
                      <div className="form-actions">
                        <button
                          type="button"
                          className="primary-link"
                          disabled={Boolean(actionBusy)}
                          onClick={() => {
                            void runPolicyAction("Approve exclusion request", async () => {
                              await reviewPolicyExclusionChangeRequest(request.id, {
                                outcome: "approved",
                                reviewComment: policyExclusionReviewComment.trim() || undefined
                              });
                              await refreshPolicyExclusionRequests(currentPolicy.id);
                            });
                          }}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="primary-link"
                          disabled={Boolean(actionBusy)}
                          onClick={() => {
                            void runPolicyAction("Reject exclusion request", async () => {
                              await reviewPolicyExclusionChangeRequest(request.id, {
                                outcome: "rejected",
                                reviewComment: policyExclusionReviewComment.trim() || undefined
                              });
                              await refreshPolicyExclusionRequests(currentPolicy.id);
                            });
                          }}
                        >
                          Reject
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))
              )}
            </div>
          </article>
        </section>
      ) : null}
    </ConsoleShell>
  );
}
