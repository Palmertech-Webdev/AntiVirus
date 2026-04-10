"use client";

import { useEffect, useMemo, useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { assignPolicy, createPolicy, updatePolicy } from "../../lib/api";
import { useConsoleData } from "./useConsoleData";
import { filterDevices } from "../../lib/console-model";

function formatBoolean(value: boolean) {
  return value ? "Enabled" : "Disabled";
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
  const [newPrivilegeHardeningEnabled, setNewPrivilegeHardeningEnabled] = useState(false);
  const [newPamLiteEnabled, setNewPamLiteEnabled] = useState(false);
  const [newDenyHighRiskElevation, setNewDenyHighRiskElevation] = useState(false);
  const [newDenyUnsignedElevation, setNewDenyUnsignedElevation] = useState(false);
  const [newRequireBreakGlassEscrow, setNewRequireBreakGlassEscrow] = useState(true);

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
  const [policyPrivilegeHardeningEnabled, setPolicyPrivilegeHardeningEnabled] = useState(false);
  const [policyPamLiteEnabled, setPolicyPamLiteEnabled] = useState(false);
  const [policyDenyHighRiskElevation, setPolicyDenyHighRiskElevation] = useState(false);
  const [policyDenyUnsignedElevation, setPolicyDenyUnsignedElevation] = useState(false);
  const [policyRequireBreakGlassEscrow, setPolicyRequireBreakGlassEscrow] = useState(true);

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
    setPolicyPrivilegeHardeningEnabled(currentPolicy.privilegeHardeningEnabled);
    setPolicyPamLiteEnabled(currentPolicy.pamLiteEnabled);
    setPolicyDenyHighRiskElevation(currentPolicy.denyHighRiskElevation);
    setPolicyDenyUnsignedElevation(currentPolicy.denyUnsignedElevation);
    setPolicyRequireBreakGlassEscrow(currentPolicy.requireBreakGlassEscrow);
    setSelectedDeviceIds(currentPolicy.assignedDeviceIds);
  }, [currentPolicy]);

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
        <article className="metric-surface">
          <span className="metric-label">PAM hardening</span>
          <strong className="metric-number">{formatBoolean(snapshot.defaultPolicy.privilegeHardeningEnabled)}</strong>
          <p className="muted-copy">No-standing-admin controls available on the current policy baseline.</p>
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
            <div className="field-group field-span-2">
              <span className="section-kicker">Privilege access management</span>
              <div className="tag-row">
                <label className="inline-toggle"><span>PAM hardening</span><input type="checkbox" checked={newPrivilegeHardeningEnabled} onChange={(event) => setNewPrivilegeHardeningEnabled(event.target.checked)} /></label>
                <label className="inline-toggle"><span>PAM lite</span><input type="checkbox" checked={newPamLiteEnabled} onChange={(event) => setNewPamLiteEnabled(event.target.checked)} /></label>
                <label className="inline-toggle"><span>Deny high-risk elevation</span><input type="checkbox" checked={newDenyHighRiskElevation} onChange={(event) => setNewDenyHighRiskElevation(event.target.checked)} /></label>
                <label className="inline-toggle"><span>Deny unsigned elevation</span><input type="checkbox" checked={newDenyUnsignedElevation} onChange={(event) => setNewDenyUnsignedElevation(event.target.checked)} /></label>
                <label className="inline-toggle"><span>Require break-glass escrow</span><input type="checkbox" checked={newRequireBreakGlassEscrow} onChange={(event) => setNewRequireBreakGlassEscrow(event.target.checked)} /></label>
              </div>
            </div>
          </div>
          <div className="form-actions">
            <button
              type="button"
              className="primary-link"
              disabled={Boolean(actionBusy) || !newPolicyName.trim()}
              onClick={() => {
                void runPolicyAction("Create policy", async () => {
                  await createPolicy({
                    name: newPolicyName.trim(),
                    description: newPolicyDescription.trim() || undefined,
                    realtimeProtection: newRealtimeProtection,
                    cloudLookup: newCloudLookup,
                    scriptInspection: newScriptInspection,
                    networkContainment: newNetworkContainment,
                    quarantineOnMalicious: newQuarantineOnMalicious,
                    privilegeHardeningEnabled: newPrivilegeHardeningEnabled,
                    pamLiteEnabled: newPamLiteEnabled,
                    denyHighRiskElevation: newDenyHighRiskElevation,
                    denyUnsignedElevation: newDenyUnsignedElevation,
                    requireBreakGlassEscrow: newRequireBreakGlassEscrow
                  });
                  setNewPolicyName("");
                  setNewPolicyDescription("");
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
              <div className="field-group field-span-2">
                <span className="section-kicker">Privilege access management</span>
                <div className="tag-row">
                  <label className="inline-toggle"><span>PAM hardening</span><input type="checkbox" checked={policyPrivilegeHardeningEnabled} onChange={(event) => setPolicyPrivilegeHardeningEnabled(event.target.checked)} /></label>
                  <label className="inline-toggle"><span>PAM lite</span><input type="checkbox" checked={policyPamLiteEnabled} onChange={(event) => setPolicyPamLiteEnabled(event.target.checked)} /></label>
                  <label className="inline-toggle"><span>Deny high-risk elevation</span><input type="checkbox" checked={policyDenyHighRiskElevation} onChange={(event) => setPolicyDenyHighRiskElevation(event.target.checked)} /></label>
                  <label className="inline-toggle"><span>Deny unsigned elevation</span><input type="checkbox" checked={policyDenyUnsignedElevation} onChange={(event) => setPolicyDenyUnsignedElevation(event.target.checked)} /></label>
                  <label className="inline-toggle"><span>Require break-glass escrow</span><input type="checkbox" checked={policyRequireBreakGlassEscrow} onChange={(event) => setPolicyRequireBreakGlassEscrow(event.target.checked)} /></label>
                </div>
              </div>
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
                      quarantineOnMalicious: policyQuarantineOnMalicious,
                      privilegeHardeningEnabled: policyPrivilegeHardeningEnabled,
                      pamLiteEnabled: policyPamLiteEnabled,
                      denyHighRiskElevation: policyDenyHighRiskElevation,
                      denyUnsignedElevation: policyDenyUnsignedElevation,
                      requireBreakGlassEscrow: policyRequireBreakGlassEscrow
                    });
                  });
                }}
              >
                Save policy
              </button>
            </div>
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
          </article>
        </section>
      ) : null}
    </ConsoleShell>
  );
}
