import { Archive, CircleCheckBig, ClipboardCheck, FilePlus2, RefreshCw, ShieldCheck } from "lucide-react";
import { getConsoleDataMode, getConsoleRepository, loadConsoleData } from "./repository";
import {
  ActionNotice,
  DataUnavailable,
  EmptyState,
  MetricCard,
  PageHeader,
  PaginationNav,
  Panel,
  RepositoryStatus,
  SecondaryLink,
  SectionHeader,
  StatusPill,
} from "./primitives";
import styles from "./console.module.css";

export interface MaskingFilters {
  cursor?: string;
  notice?: string;
  error?: string;
  show_archived?: string;
}

export async function MaskingView({ filters }: { filters: MaskingFilters }) {
  const state = await loadConsoleData(() => getConsoleRepository().getMaskingPolicies({ cursor: filters.cursor, limit: 25 }));
  const live = getConsoleDataMode() === "api";
  if (state.status === "error") {
    return (
      <>
        <PageHeader eyebrow="Data masking" title="Masking governance" description="Create and verify a bounded masked copy in a separate local MySQL database." />
        <ActionNotice notice={filters.notice} error={filters.error} />
        <DataUnavailable state={state} />
      </>
    );
  }

  const allPolicies = state.result.value.items;
  const showArchived = filters.show_archived === "1";
  const maskingPolicies = showArchived ? allPolicies : allPolicies.filter((policy) => !policy.archived);
  const archivedCount = allPolicies.filter((policy) => policy.archived).length;
  const drafts = maskingPolicies.filter((policy) => policy.workflowStatus === "draft").length;
  const approved = maskingPolicies.filter((policy) => policy.workflowStatus === "approved").length;
  const validated = maskingPolicies.filter((policy) => policy.workflowStatus === "validated").length;
  const activeCopies = maskingPolicies.filter((policy) => ["queued", "running", "retry_pending"].includes(policy.copyStatus ?? "")).length;
  const checkedCopies = maskingPolicies.filter((policy) => policy.automatedChecksPassed).length;

  return (
    <>
      <PageHeader
        eyebrow="Data masking"
        title="Masking governance"
        description="Create and verify a bounded masked copy in a separate local MySQL database."
        actions={<SecondaryLink href="#create-masking-plan">Start another workflow</SecondaryLink>}
      />
      <ActionNotice notice={filters.notice} error={filters.error} />
      <RepositoryStatus meta={state.result.meta} />

      <div className={styles.insightStrip} role="note">
        <ShieldCheck size={20} aria-hidden="true" />
        <div>
          <strong>Fixed local boundary</strong>
          <span>The source insurance_sample is read-only. Every approved workflow receives its own server-derived local masked database, so it can run from start to finish without overwriting an earlier result; it never connects to Azure SQL.</span>
        </div>
      </div>

      <section className={styles.metricGrid} aria-label="Masking workflow summary">
        <MetricCard label="Active workflows" value={String(maskingPolicies.filter((policy) => !policy.archived).length)} helper={`${archivedCount} completed workflow${archivedCount === 1 ? "" : "s"} archived`} icon={ClipboardCheck} />
        <MetricCard label="Draft" value={String(drafts)} helper="waiting for approval" tone={drafts ? "warning" : "good"} icon={FilePlus2} />
        <MetricCard label="Copy jobs active" value={String(activeCopies)} helper="queued, running, or safely retrying" tone={activeCopies ? "warning" : "good"} icon={RefreshCw} />
        <MetricCard label="Automated checks passed" value={String(checkedCopies)} helper={`${approved} approved · ${validated} human validated`} tone="good" icon={CircleCheckBig} />
      </section>

      <div className={styles.nextActionStrip} role="status">
        <strong>Next recommended action</strong>
        <span>{maskingNextAction(maskingPolicies)}</span>
        {activeCopies ? <SecondaryLink href="/console/masking">Refresh status</SecondaryLink> : <SecondaryLink href="#create-masking-plan">Start or continue</SecondaryLink>}
      </div>

      <Panel className={styles.workflowPanel}>
        <SectionHeader title="Simple governed workflow" description="Only the dedicated local worker performs the copy; the normal assessment collector remains read-only." />
        <ol className={styles.workflowSteps}>
          <li><span>01</span><div><strong>Create draft</strong><p>Describe the data class, technique, and safe target environment.</p></div></li>
          <li><span>02</span><div><strong>Approve plan</strong><p>Confirm that the proposed plan is suitable before any external work.</p></div></li>
          <li><span>03</span><div><strong>Create masked copy</strong><p>Read at most 500 rows per source table and publish to this workflow&apos;s separate local target database.</p></div></li>
          <li><span>04</span><div><strong>Review and validate</strong><p>Confirm unchanged-source, row-count, manifest, and foreign-key proof before the analyst decision.</p></div></li>
        </ol>
      </Panel>

      <Panel className={styles.actionPanel}>
        <div id="create-masking-plan" className={styles.anchorTarget} aria-hidden="true" />
        <SectionHeader title="Create a masking plan" description={live ? "Start with a draft. Nothing is sent to MySQL." : "Connect the live local API to save a draft."} />
        <form className={styles.actionForm} action="/console/actions/masking-policies" method="post" aria-label="Create a masking policy draft">
          <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
          <label className={styles.formField}><span>Plan name</span><input name="name" required maxLength={160} placeholder="Customer identifiers" disabled={!live} /></label>
          <label className={styles.formField}><span>Classification</span><input value="Restricted and confidential" readOnly disabled={!live} /><input type="hidden" name="classification" value="Restricted and confidential" /></label>
          <label className={styles.formField}><span>Technique</span><input value="Substitute" readOnly disabled={!live} /><input type="hidden" name="strategy" value="substitute" /></label>
          <label className={styles.formField}><span>Target environment</span><input value="Development" readOnly disabled={!live} /><input type="hidden" name="target_environment" value="development" /></label>
          <p className={styles.formHint}>Do not enter passwords, connection strings, customer values, or other secrets.</p>
          <div className={styles.formActions}><button className={styles.formSubmit} type="submit" disabled={!live}>Create draft</button></div>
        </form>
      </Panel>

      <Panel>
        <div className={styles.sectionHeaderWithAction}>
          <SectionHeader title="Masking plans" description="Advance each plan one controlled step at a time. Completed workflows can be archived without deleting their evidence or databases." />
          <SecondaryLink href={showArchived ? "/console/masking" : "/console/masking?show_archived=1"}>{showArchived ? "Hide archived" : `Show archived (${archivedCount})`}</SecondaryLink>
        </div>
        {maskingPolicies.length ? (
          <div className={styles.policyWorkflowList}>
            {maskingPolicies.map((policy) => {
              const nextAction = policy.workflowStatus === "draft"
                ? "approve"
                : policy.workflowStatus === "approved" && !policy.isBuiltinLocalCopy
                  ? "record_execution"
                  : policy.workflowStatus === "execution_recorded"
                    ? "validate"
                    : null;
              const buttonLabel = nextAction === "approve" ? "Approve plan" : nextAction === "record_execution" ? "Record execution" : nextAction === "validate" ? "Validate evidence" : null;
              return (
                <article className={styles.policyWorkflowCard} key={policy.id}>
                  <header>
                    <div className={styles.primaryCell}><strong>{policy.name}</strong><span>{policy.classification} · {policy.technique} · {policy.environment}</span></div>
                    <StatusPill status={policy.status} />
                  </header>
                  <div className={styles.policyStep} aria-label={`Workflow step ${workflowStep(policy)} of 4`}>
                    <span>Step {workflowStep(policy)} of 4</span>
                    <div><i style={{ width: `${workflowStep(policy) * 25}%` }} /></div>
                    <strong>{workflowStepLabel(policy)}</strong>
                  </div>
                  <dl>
                    <div><dt>Database boundary</dt><dd>{policy.isBuiltinLocalCopy ? `${policy.sourceDatabase} → ${policy.targetDatabase}` : policy.datasets ? `${policy.datasets} datasets recorded` : "Scope will be confirmed before execution"}</dd></div>
                    <div><dt>Copy status</dt><dd>{policy.isBuiltinLocalCopy ? copyStatusLabel(policy.copyStatus) : policy.executionReference ?? "Not recorded"}</dd></div>
                    <div><dt>Latest note</dt><dd>{policy.lastNote ?? "No review note yet"}</dd></div>
                    <div><dt>Safety proof</dt><dd>{policy.automatedChecksPassed ? `${policy.rowsCopied ?? 0} rows · ${policy.columnsMasked ?? 0} columns masked` : policy.isBuiltinLocalCopy ? `500 rows maximum per table · source read-only` : policy.lastValidated}</dd></div>
                  </dl>
                  {policy.isBuiltinLocalCopy && policy.workflowStatus === "approved" && !["queued", "running", "retry_pending"].includes(policy.copyStatus ?? "") ? (
                    <form className={styles.policyWorkflowForm} action="/console/actions/masking-policies/copy" method="post" aria-label={`Create local masked copy for ${policy.name}`}>
                      <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
                      <input type="hidden" name="policy_id" value={policy.id} />
                      <div className={styles.primaryCell}>
                        <strong>{policy.copyStatus === "failed" ? "Retry this bounded copy" : "Create this workflow's bounded local copy"}</strong>
                        <span>This workflow writes only to its separate target {policy.targetDatabase}. The source and earlier workflow targets are not overwritten.</span>
                      </div>
                      <button className={styles.formSubmit} type="submit" disabled={!live}>{policy.copyStatus === "failed" ? "Retry masked copy" : "Create masked copy"}</button>
                    </form>
                  ) : policy.isBuiltinLocalCopy && policy.workflowStatus === "approved" ? (
                    <div className={styles.policyComplete}><RefreshCw size={15} aria-hidden="true" /><span>{copyStatusLabel(policy.copyStatus)}.</span><SecondaryLink href="/console/masking">Refresh status</SecondaryLink></div>
                  ) : null}
                  {nextAction && buttonLabel ? (
                    <form className={styles.policyWorkflowForm} action="/console/actions/masking-policies/workflow" method="post" aria-label={`${buttonLabel} for ${policy.name}`}>
                      <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
                      <input type="hidden" name="policy_id" value={policy.id} />
                      <input type="hidden" name="action" value={nextAction} />
                      <label className={styles.formField}><span>Review note</span><input name="note" required minLength={3} maxLength={1000} placeholder="Describe the review evidence" disabled={!live} /></label>
                      {nextAction === "record_execution" ? (
                        <label className={styles.formField}><span>External reference</span><input name="reference" required maxLength={240} placeholder="Ticket or job ID (no secrets)" disabled={!live} /></label>
                      ) : <input type="hidden" name="reference" value="" />}
                      <button className={styles.formSubmit} type="submit" disabled={!live}>{buttonLabel}</button>
                    </form>
                  ) : policy.workflowStatus === "validated" && !policy.archived ? (
                    <div className={styles.completedWorkflowActions}>
                      <p className={styles.policyComplete}><CircleCheckBig size={15} aria-hidden="true" />Workflow evidence is complete. Its masked target and evidence remain available.</p>
                      <form className={styles.archiveForm} action="/console/actions/masking-policies/workflow" method="post" aria-label={`Archive ${policy.name}`}>
                        <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
                        <input type="hidden" name="policy_id" value={policy.id} />
                        <input type="hidden" name="action" value="archive" />
                        <input type="hidden" name="reference" value="" />
                        <label className={styles.formField}><span>Archive reason</span><input name="note" required minLength={3} maxLength={1000} placeholder="Completed and retained for audit" disabled={!live} /></label>
                        <button className={styles.secondaryButton} type="submit" disabled={!live}><Archive size={14} aria-hidden="true" />Archive workflow</button>
                      </form>
                    </div>
                  ) : policy.archived ? (
                    <p className={styles.policyComplete}><Archive size={15} aria-hidden="true" />Archived {policy.archivedAt ? new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(new Date(policy.archivedAt)) : "after completion"}. Evidence and the masked target were retained.</p>
                  ) : null}
                </article>
              );
            })}
          </div>
        ) : <EmptyState title="No masking plans" message="Create a draft above to begin the local governance workflow." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/masking" params={{ show_archived: showArchived ? "1" : "" }} />
      </Panel>
    </>
  );
}

function workflowStep(policy: import("./data").MaskingPolicy): number {
  if (policy.workflowStatus === "validated") return 4;
  if (policy.workflowStatus === "execution_recorded") return 3;
  if (policy.workflowStatus === "approved") return 2;
  return 1;
}

function workflowStepLabel(policy: import("./data").MaskingPolicy): string {
  if (policy.archived) return "Completed and archived";
  if (policy.workflowStatus === "validated") return "Human validation complete";
  if (policy.workflowStatus === "execution_recorded") return "Review the automated proof";
  if (policy.workflowStatus === "approved") return ["queued", "running", "retry_pending"].includes(policy.copyStatus ?? "") ? "Masked copy is processing" : "Create the bounded masked copy";
  return "Review and approve the plan";
}

function maskingNextAction(policies: readonly import("./data").MaskingPolicy[]): string {
  if (policies.some((policy) => ["queued", "running", "retry_pending"].includes(policy.copyStatus ?? ""))) return "A local copy job is active. Refresh this page until the automated checks finish.";
  if (policies.some((policy) => policy.workflowStatus === "execution_recorded" && !policy.archived)) return "Test the newest masked target with the read-only test account, add a clear review note, then validate its evidence.";
  if (policies.some((policy) => policy.workflowStatus === "approved" && !policy.archived)) return "Create or retry the approved workflow's separate local masked copy.";
  if (policies.some((policy) => policy.workflowStatus === "draft" && !policy.archived)) return "Review the draft scope, enter an approval note, and approve the plan.";
  return "Create a new draft to run another independent masking workflow from start to finish.";
}

function copyStatusLabel(status: import("./data").MaskingPolicy["copyStatus"]): string {
  if (status === "queued") return "Queued for the local masker";
  if (status === "running") return "Copy running inside the local boundary";
  if (status === "retry_pending") return "Retry scheduled after a safe failure";
  if (status === "failed") return "Copy failed; no success evidence recorded";
  if (status === "automated_checks_passed") return "Automated copy checks passed";
  return "Not started";
}
