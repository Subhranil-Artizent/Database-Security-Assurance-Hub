import { CircleCheckBig, Clock3, ShieldAlert, TriangleAlert } from "lucide-react";
import type { FindingStatus } from "./data";
import { getConsoleDataMode, getConsoleRepository, loadConsoleData } from "./repository";
import { ActionNotice, DataUnavailable, FilterBar, FilterField, MetricCard, NoResults, PageHeader, PaginationNav, Panel, PlatformBadge, RepositoryStatus, SecondaryLink, SectionHeader, SeverityPill, StatusPill } from "./primitives";
import styles from "./console.module.css";

export interface FindingFilters { severity?: string; status?: string; platform?: string; cursor?: string; notice?: string; error?: string }

export async function FindingsView({ filters }: { filters: FindingFilters }) {
  const state = await loadConsoleData(() => getConsoleRepository().getFindings({ cursor: filters.cursor, limit: 25, status: filters.status }));
  const live = getConsoleDataMode() === "api";
  if (state.status === "error") {
    return (
      <>
        <PageHeader eyebrow="Risk workflow" title="Security findings" description="Prioritized control gaps with accountable ownership, evidence, due dates, and remediation guidance." />
        <ActionNotice notice={filters.notice} error={filters.error} />
        <DataUnavailable state={state} />
      </>
    );
  }
  const findings = state.result.value.items;
  const filtered = findings.filter((finding) => {
    const severity = !filters.severity || filters.severity === "all" || finding.severity === filters.severity;
    const status = !filters.status || filters.status === "all" || finding.status === filters.status;
    const platform = !filters.platform || filters.platform === "all" || finding.platform === filters.platform;
    return severity && status && platform;
  });

  return (
    <>
      <PageHeader eyebrow="Risk workflow" title="Security findings" description="Prioritized control gaps with accountable ownership, evidence, due dates, and remediation guidance." />
      <ActionNotice notice={filters.notice} error={filters.error} />
      <RepositoryStatus meta={state.result.meta} />
      <section className={styles.metricGrid} aria-label="Finding summary">
        <MetricCard label="Critical" value={String(findings.filter((finding) => finding.severity === "Critical").length)} helper="visible on this page" tone="critical" icon={TriangleAlert} />
        <MetricCard label="High" value={String(findings.filter((finding) => finding.severity === "High").length)} helper="visible on this page" tone="warning" icon={ShieldAlert} />
        <MetricCard label="In remediation" value={String(findings.filter((finding) => finding.status === "In remediation").length)} helper="with assigned workflow state" icon={Clock3} />
        <MetricCard label="Resolved" value={String(findings.filter((finding) => finding.status === "Resolved").length)} helper="visible on this page" tone="good" icon={CircleCheckBig} />
      </section>

      <Panel>
        <SectionHeader title="Prioritized remediation queue" description={`${filtered.length} findings match on this page`} />
        <form action="/console/findings" method="get" aria-label="Filter security findings">
          <FilterBar>
            <FilterField label="Severity" name="severity" defaultValue={filters.severity}>
              <option value="all">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
            </FilterField>
            <FilterField label="Workflow state" name="status" defaultValue={filters.status}>
              <option value="all">All workflow states</option><option>Open</option><option>In remediation</option><option>Risk accepted</option><option>Resolved</option><option>False positive</option>
            </FilterField>
            <FilterField label="Platform" name="platform" defaultValue={filters.platform}>
              <option value="all">All platforms</option><option>Oracle</option><option>PostgreSQL</option><option>Sybase ASE</option><option>MySQL</option>
            </FilterField>
            <button className={styles.filterButton} type="submit">Apply filters</button>
          </FilterBar>
        </form>
        {filtered.length ? (
          <div className={styles.findingList}>
            {filtered.map((finding) => (
              <article className={styles.findingCard} key={finding.id}>
                <div className={styles.findingTitleBlock}>
                  <div><SeverityPill severity={finding.severity} /><span className={styles.recordId}>{finding.id}</span></div>
                  <h3>{finding.title}</h3>
                  <p>{finding.asset} · {finding.control}</p>
                </div>
                <div className={styles.findingMeta}>
                  <PlatformBadge platform={finding.platform} />
                  <div><span>Owner</span><strong>{finding.owner}</strong></div>
                  <div><span>Due</span><strong>{finding.dueDate}</strong></div>
                  <StatusPill status={finding.status} />
                </div>
                <details className={styles.findingDetails}>
                  <summary>View evidence and remediation</summary>
                  <div>
                    <section><span>Evidence</span><p>{finding.evidence}</p></section>
                    <section><span>Recommended remediation</span><p>{finding.remediation}</p></section>
                  </div>
                  {finding.assessmentId ? <div className={styles.formActions}><SecondaryLink href={`/console/assessments/${encodeURIComponent(finding.assessmentId)}`}>Review source decisions</SecondaryLink></div> : null}
                  {live && isEditableFindingStatus(finding.status) ? <form className={styles.findingWorkflowForm} action="/console/actions/findings" method="post" aria-label={`Update finding ${finding.id}`}>
                    <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
                    <input type="hidden" name="finding_id" value={finding.id} />
                    <label className={styles.formField}><span>Workflow state</span><select name="status" defaultValue={findingStatusValue(finding.status)}><option value="open">Open</option><option value="in_progress">In remediation</option><option value="resolved">Resolved</option></select></label>
                    <label className={styles.formField}><span>Owner</span><input name="owner" maxLength={160} defaultValue={finding.owner === "Unassigned" ? "" : finding.owner} /></label>
                    <label className={styles.formField}><span>Due date</span><input name="due_date" type="date" defaultValue={finding.dueAt?.slice(0, 10)} /></label>
                    <label className={styles.formField}><span>Audit reason</span><input name="reason" required minLength={3} maxLength={2000} placeholder="Reason for this workflow change" /></label>
                    <button className={styles.formSubmit} type="submit">Save workflow</button>
                  </form> : live ? <p className={styles.formHint}>This governed disposition is read-only here. Risk acceptance can only change through the separate exception request, independent approval, and revocation workflow.</p> : null}
                </details>
              </article>
            ))}
          </div>
        ) : <NoResults message="No findings match the selected filters." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/findings" params={filters} />
      </Panel>
    </>
  );
}

type EditableFindingStatus = Extract<FindingStatus, "Open" | "In remediation" | "Resolved">;

function isEditableFindingStatus(status: FindingStatus): status is EditableFindingStatus {
  return status === "Open" || status === "In remediation" || status === "Resolved";
}

function findingStatusValue(status: EditableFindingStatus): string {
  if (status === "In remediation") return "in_progress";
  return status.toLowerCase();
}
