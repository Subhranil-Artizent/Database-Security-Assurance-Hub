import { Database, EyeOff, ScanSearch, ShieldCheck } from "lucide-react";
import { getConsoleRepository, loadConsoleData } from "./repository";
import { DataUnavailable, MetricCard, PageHeader, PaginationNav, Panel, PlatformBadge, Progress, RepositoryStatus, SectionHeader, StatusPill, TableFrame } from "./primitives";
import styles from "./console.module.css";

export async function DiscoveryView({ cursor }: { cursor?: string }) {
  const state = await loadConsoleData(() => getConsoleRepository().getSensitiveColumns({ cursor, limit: 25 }));
  if (state.status === "error") return <><PageHeader eyebrow="Data protection" title="Sensitive-data discovery" description="Metadata-first classification of sensitive information without moving production values into the assurance platform." /><DataUnavailable state={state} /></>;
  const sensitiveColumns = state.result.value.items;
  const tableCount = new Set(sensitiveColumns.map((column) => `${column.asset}:${column.schema}:${column.table}`)).size;
  const assetCount = new Set(sensitiveColumns.map((column) => column.asset)).size;
  const restrictedCount = sensitiveColumns.filter((column) => column.classification === "Restricted").length;
  const confidentialCount = sensitiveColumns.filter((column) => column.classification === "Confidential").length;
  const internalCount = sensitiveColumns.filter((column) => column.classification === "Internal").length;
  const protectedCount = sensitiveColumns.filter((column) => !["Unknown", "Unprotected"].includes(column.protection)).length;
  const unknownProtectionCount = sensitiveColumns.filter((column) => column.protection === "Unknown").length;
  const protectionCoverage = sensitiveColumns.length ? Math.round((protectedCount / sensitiveColumns.length) * 100) : 0;
  const platformCoverage = (["Oracle", "PostgreSQL", "Sybase ASE", "MySQL"] as const)
    .map((platform) => ({ platform, columns: sensitiveColumns.filter((column) => column.platform === platform).length }))
    .filter((entry) => entry.columns > 0);
  return (
    <>
      <PageHeader eyebrow="Data protection" title="Sensitive-data discovery" description="Metadata-first classification of sensitive information without moving production values into the assurance platform." />
      <RepositoryStatus meta={state.result.meta} />
      <div className={styles.demoNoticeInline}><ShieldCheck size={17} aria-hidden="true" /><p><strong>Privacy-preserving by design.</strong> Classification results retain schema metadata and confidence only; representative values are never shown.</p></div>
      <section className={styles.metricGrid} aria-label="Discovery summary">
        <MetricCard label="Objects catalogued" value={String(tableCount)} helper={`${assetCount} local database asset${assetCount === 1 ? "" : "s"}`} icon={Database} />
        <MetricCard label="Sensitive columns" value={String(sensitiveColumns.length)} helper={`${restrictedCount} classified as restricted`} icon={ScanSearch} />
        <MetricCard label="Protection reported" value={`${protectionCoverage}%`} helper="No row values inspected" tone={protectionCoverage ? "good" : "warning"} icon={ShieldCheck} />
        <MetricCard label="Needs validation" value={String(unknownProtectionCount)} helper="Protection state is not inferred from names" tone="warning" icon={EyeOff} />
      </section>

      <div className={styles.discoveryGrid}>
        <Panel>
          <SectionHeader title="Classification distribution" description="Columns grouped by handling requirement" />
          <div className={styles.classificationList}>
            <div><span className={styles.restrictedMark} /><div><strong>Restricted</strong><small>Regulated identifiers and financial data</small></div><b>{restrictedCount}</b></div>
            <div><span className={styles.confidentialMark} /><div><strong>Confidential</strong><small>Personal and business-confidential data</small></div><b>{confidentialCount}</b></div>
            <div><span className={styles.internalMark} /><div><strong>Internal</strong><small>Operational metadata and telemetry</small></div><b>{internalCount}</b></div>
          </div>
        </Panel>
        <Panel>
          <SectionHeader title="Discovery coverage" description="Metadata successfully evaluated by platform" />
          <div className={styles.coverageList}>
            {platformCoverage.map((entry) => <div key={entry.platform}><PlatformBadge platform={entry.platform} /><Progress value={100} label={`${entry.columns} classified columns`} /></div>)}
          </div>
        </Panel>
      </div>

      <Panel>
        <SectionHeader title="Sensitive column inventory" description="Deterministic classifications from column names and types; database values are never read" />
        <TableFrame label="Sensitive column inventory">
          <table className={styles.dataTable}>
            <thead><tr><th>Data location</th><th>Platform</th><th>Classification</th><th>Data type</th><th>Confidence</th><th>Protection state</th></tr></thead>
            <tbody>
              {sensitiveColumns.map((column) => (
                <tr key={column.id}>
                  <td><div className={styles.primaryCell}><strong>{column.schema}.{column.table}.{column.column}</strong><span>{column.asset} · {column.id}</span></div></td>
                  <td><PlatformBadge platform={column.platform} /></td>
                  <td><span className={`${styles.classificationBadge} ${styles[column.classification.toLowerCase()]}`}>{column.classification}</span></td>
                  <td><code className={styles.dataType}>{column.dataType}</code></td>
                  <td><Progress value={column.confidence} /></td>
                  <td><div className={styles.stackedCell}><StatusPill status={column.protection === "Unknown" ? "Pending" : column.protection === "Unprotected" ? "Needs attention" : "Healthy"} /><small>{column.protection}</small></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableFrame>
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/data-discovery" />
      </Panel>
    </>
  );
}
