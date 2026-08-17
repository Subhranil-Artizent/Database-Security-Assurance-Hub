import { Archive, CircleCheckBig, FileCheck2, History } from "lucide-react";
import { getConsoleRepository, loadConsoleData } from "./repository";
import { DataUnavailable, DateChip, EmptyState, MetricCard, PageHeader, PaginationNav, Panel, PlatformBadge, RepositoryStatus, SectionHeader, StatusPill, TableFrame } from "./primitives";
import styles from "./console.module.css";

export interface EvidenceFilters {
  cursor?: string;
  assessment_id?: string;
  control_id?: string;
}

export async function EvidenceView({ filters }: { filters: EvidenceFilters }) {
  const state = await loadConsoleData(() => getConsoleRepository().getEvidenceRecords({
    cursor: filters.cursor,
    limit: 25,
    assessmentId: filters.assessment_id,
    controlId: filters.control_id,
  }));
  if (state.status === "error") return <><PageHeader eyebrow="Audit readiness" title="Evidence library" description="Immutable, time-stamped control evidence with collection lineage, integrity state, and policy-based retention." /><DataUnavailable state={state} /></>;
  const evidenceRecords = state.result.value.items;
  return (
    <>
      <PageHeader
        eyebrow="Audit readiness"
        title="Evidence library"
        description="Immutable, time-stamped control evidence with collection lineage, recorded digests, and policy-based retention."
      />
      <RepositoryStatus meta={state.result.meta} />
      <section className={styles.metricGrid} aria-label="Evidence summary">
        <MetricCard label="Evidence objects" value={String(evidenceRecords.length)} helper="visible on this page" icon={FileCheck2} />
        <MetricCard label="Digests recorded" value={String(evidenceRecords.filter((record) => record.integrity === "Digest recorded").length)} helper="server-stored SHA-256 values" tone="good" icon={CircleCheckBig} />
        <MetricCard label="Freshness state" value={state.result.meta.stale ? "Stale" : "Current"} helper="reported by the control plane" tone={state.result.meta.stale ? "warning" : "good"} icon={History} />
        <MetricCard label="Policy retained" value={String(evidenceRecords.filter((record) => record.retention !== "Not reported").length)} helper="with retention classification" icon={Archive} />
      </section>

      <div className={styles.integrityBanner}>
        <span className={styles.integrityIcon}><CircleCheckBig size={20} aria-hidden="true" /></span>
        <div><strong>{evidenceRecords.length > 0 && evidenceRecords.every((record) => record.integrity === "Digest recorded") ? "Visible evidence has a recorded digest" : "Some evidence is missing a digest"}</strong><p>{evidenceRecords.length ? `${evidenceRecords.filter((record) => record.integrity === "Digest recorded").length} of ${evidenceRecords.length} visible records include a stored SHA-256 digest. A recorded digest is provenance data, not an independent re-verification.` : "No evidence records are available."}</p></div>
        <DateChip>Loaded {new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeZone: "Asia/Kolkata" }).format(new Date(state.result.meta.fetchedAt))}</DateChip>
      </div>

      <Panel>
        <SectionHeader title="Recent evidence" description="Records generated from approved read-only collection and controlled local masking-copy checks" />
        {evidenceRecords.length ? <TableFrame label="Evidence record library">
          <table className={styles.dataTable}>
            <thead><tr><th>Control evidence</th><th>Asset</th><th>Platform</th><th>Source</th><th>Collected at</th><th>Digest</th><th>Retention</th></tr></thead>
            <tbody>
              {evidenceRecords.map((record) => (
                <tr key={record.id}>
                  <td><div className={styles.primaryCell}><strong>{record.control}</strong><span>{record.id}</span></div></td>
                  <td><code className={styles.assetCode}>{record.asset}</code></td>
                  <td><PlatformBadge platform={record.platform} /></td>
                  <td className={styles.mutedCell}>{record.source}</td>
                  <td className={styles.mutedCell}>{record.collectedAt}</td>
                  <td><StatusPill status={record.integrity} /></td>
                  <td><span className={styles.retentionBadge}>{record.retention}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableFrame> : <EmptyState title="No evidence collected" message="Evidence appears after a collector completes an assessment." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/evidence" params={filters} />
      </Panel>
    </>
  );
}
