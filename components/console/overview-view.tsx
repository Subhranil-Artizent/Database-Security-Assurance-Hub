import { Activity, Database, FileCheck2, ShieldCheck, TriangleAlert } from "lucide-react";
import { getConsoleRepository, loadConsoleData } from "./repository";
import { DataUnavailable, EmptyState, MetricCard, PageHeader, Panel, PlatformBadge, PrimaryLink, Progress, RepositoryStatus, ScoreRing, SecondaryLink, SectionHeader, SeverityPill, StatusPill, TableFrame } from "./primitives";
import styles from "./console.module.css";

export async function OverviewView() {
  const state = await loadConsoleData(() => getConsoleRepository().getOverview());
  if (state.status === "error") {
    return <><PageHeader eyebrow="Command center" title="Security assurance overview" description="A unified, evidence-backed view of database protection across the enterprise estate." /><DataUnavailable state={state} /></>;
  }
  const { assuranceTrend, controlDomains, platformSummary, recentActivity, totals } = state.result.value;
  const scoredDomains = controlDomains.filter((domain) => domain.scoreAvailable ?? domain.controls > 0);
  const assuranceScore = scoredDomains.length ? Math.round(scoredDomains.reduce((sum, domain) => sum + domain.score, 0) / scoredDomains.length) : null;
  const trendChange = assuranceTrend.length > 1 ? (assuranceTrend.at(-1) ?? 0) - assuranceTrend[0] : null;

  return (
    <>
      <PageHeader
        eyebrow="Command center"
        title="Security assurance overview"
        description="A unified, evidence-backed view of database protection across the enterprise estate."
        actions={<><SecondaryLink href="/console/report">Management report</SecondaryLink><PrimaryLink href="/console/assessments">Run assessment</PrimaryLink></>}
      />
      <RepositoryStatus meta={state.result.meta} />

      <div className={styles.nextActionStrip} role="note">
        <strong>How to read the score</strong>
        <span>Each finalized assessment uses Passed ÷ (Passed + Failed) × 100. Not-applicable controls are excluded, and collected evidence is never treated as an automatic pass.</span>
        <SecondaryLink href="/console/report">Open report</SecondaryLink>
      </div>

      <section className={styles.metricGrid} aria-label="Assurance summary">
        <MetricCard label="Assurance score" value={assuranceScore === null ? "Not scored" : `${assuranceScore}/100`} helper={assuranceScore === null ? "awaiting analyst decisions" : "from completed visible assessments"} tone={assuranceScore === null || assuranceScore >= 80 ? "good" : "warning"} icon={ShieldCheck} />
        <MetricCard label="Database assets" value={String(totals.assets)} helper="tenant-scoped managed inventory" icon={Database} />
        <MetricCard label="Open findings" value={String(totals.openFindings)} helper="requiring governance workflow" tone="warning" icon={TriangleAlert} />
        <MetricCard label="Assessments" value={String(totals.assessments)} helper="versioned control evaluations" icon={FileCheck2} />
      </section>

      <div className={styles.overviewGrid}>
        <Panel className={styles.assurancePanel}>
          <SectionHeader title="Enterprise assurance posture" description="Calculated from completed, tenant-scoped assessment results" href="/console/assessments" linkLabel="Explore assessments" />
          <div className={styles.assuranceBody}>
            {assuranceScore === null ? <EmptyState title="Not scored yet" message="The MySQL evidence is collected first; a score appears only after an analyst decision." /> : <ScoreRing value={assuranceScore} size="large" />}
            <div className={styles.trendBlock}>
              <div className={styles.trendHeader}>
                <span>Recent trend</span>
                <strong>{trendChange === null ? "Awaiting trend" : `${trendChange >= 0 ? "+" : ""}${trendChange} pts`}</strong>
              </div>
              <div className={styles.barChart} role="img" aria-label={assuranceTrend.length ? `Recent assurance scores: ${assuranceTrend.join(", ")}.` : "No completed assessment trend is available."}>
                {assuranceTrend.map((value, index) => (
                  <div key={`${value}-${index}`} aria-hidden="true">
                    <span style={{ height: `${Math.max(12, value * 0.9)}px` }} />
                    <small>R{index + 1}</small>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className={styles.domainGrid}>
            {controlDomains.map((domain) => (
              <article key={domain.name}>
                <div><strong>{domain.name}</strong><span>{domain.scoreAvailable ? `${domain.change > 0 ? "+" : ""}${domain.change} pts` : "Pending review"}</span></div>
                <Progress value={domain.scoreAvailable ? domain.score : 0} tone={!domain.scoreAvailable || domain.score < 72 ? "warning" : "good"} />
                <small>{domain.controls} assessments · {domain.findings} findings</small>
              </article>
            ))}
          </div>
        </Panel>

        <Panel className={styles.activityPanel}>
          <SectionHeader title="Recent control activity" description="Assessment and finding lifecycle events" href="/console/evidence" linkLabel="Evidence library" />
          {recentActivity.length ? <ol className={styles.activityList}>
            {recentActivity.map((activity) => (
              <li key={`${activity.time}-${activity.title}`}>
                <span className={`${styles.activityMarker} ${styles[activity.tone]}`} aria-hidden="true" />
                <time>{activity.time}</time>
                <div><strong>{activity.title}</strong><p>{activity.detail}</p></div>
              </li>
            ))}
          </ol> : <EmptyState title="No recent control activity" message="Assessment and finding events will appear here." />}
          <div className={styles.automationBanner}>
            <Activity size={17} aria-hidden="true" />
            <div><strong>Bounded recovery controls</strong><span>{totals.connectors} registered collectors use leased work and retry limits</span></div>
            <StatusPill status={totals.connectors > 0 ? "Online" : "Offline"} />
          </div>
        </Panel>
      </div>

      <Panel>
        <SectionHeader title="Platform coverage" description="Current assurance state across the supported database estate" href="/console/assets" linkLabel="View all assets" />
        {platformSummary.some((row) => row.assets > 0) ? <TableFrame label="Platform coverage table">
          <table className={styles.dataTable}>
            <thead><tr><th>Platform</th><th>Assets</th><th>Assessment score</th><th>Open findings</th><th>Latest assessment</th><th>State</th></tr></thead>
            <tbody>
              {platformSummary.map((row) => (
                <tr key={row.platform}>
                  <td><PlatformBadge platform={row.platform} /></td>
                  <td><strong>{row.assets}</strong></td>
                  <td>{(row.scoreAvailable ?? row.coverage > 0) ? <Progress value={row.coverage} tone={row.coverage < 70 ? "warning" : "good"} /> : <span className={styles.mutedCell}>Pending analyst review</span>}</td>
                  <td>{row.openFindings > 7 ? <SeverityPill severity="High" /> : <span className={styles.findingCount}>{row.openFindings}</span>}</td>
                  <td className={styles.mutedCell}>{row.lastScan}</td>
                  <td><StatusPill status={row.assets === 0 ? "Offline" : !(row.scoreAvailable ?? row.coverage > 0) ? "Pending" : row.coverage < 70 ? "Needs attention" : "Healthy"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableFrame> : <EmptyState title="No database assets connected" message="Register database metadata and an approved private collector to begin assurance reporting." />}
      </Panel>

      <div className={styles.insightStrip}>
        <FileCheck2 size={20} aria-hidden="true" />
        <div><strong>Evidence-backed reporting</strong><span>Review control evidence and freshness before publishing an assurance pack.</span></div>
        <PrimaryLink href="/console/evidence">Review evidence</PrimaryLink>
      </div>
    </>
  );
}
