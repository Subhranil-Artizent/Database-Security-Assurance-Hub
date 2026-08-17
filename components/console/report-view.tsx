import { Database, FileCheck2, ShieldCheck, TriangleAlert } from "lucide-react";
import { getConsoleRepository, getLocalMySqlMode, loadConsoleData } from "./repository";
import { DataUnavailable, MetricCard, PageHeader, Panel, RepositoryStatus, SectionHeader, StatusPill } from "./primitives";
import { PrintReportButton } from "./print-report-button";
import styles from "./console.module.css";

export async function ReportView() {
  const state = await loadConsoleData(async () => {
    const repository = getConsoleRepository();
    const [overview, assets, assessments, findings, evidence, masking] = await Promise.all([
      repository.getOverview(),
      repository.getAssets({ limit: 100 }),
      repository.getAssessments({ limit: 100 }),
      repository.getFindings({ limit: 100 }),
      repository.getEvidenceRecords({ limit: 100 }),
      repository.getMaskingPolicies({ limit: 100 }),
    ]);
    return {
      value: {
        overview: overview.value,
        assets: assets.value.items,
        assessments: assessments.value.items,
        findings: findings.value.items,
        evidence: evidence.value.items,
        masking: masking.value.items,
      },
      meta: overview.meta,
    };
  });

  if (state.status === "error") {
    return <><PageHeader eyebrow="Management report" title="Database security assurance report" description="A printable summary of the visible assurance record." /><DataUnavailable state={state} /></>;
  }

  const { overview, assets, assessments, findings, evidence, masking } = state.result.value;
  const scoredDomains = overview.controlDomains.filter((domain) => domain.scoreAvailable ?? domain.controls > 0);
  const assuranceScore = scoredDomains.length ? Math.round(scoredDomains.reduce((sum, domain) => sum + domain.score, 0) / scoredDomains.length) : null;
  const unresolvedFindings = findings.filter((finding) => !["Resolved", "False positive"].includes(finding.status));
  const completedAssessments = assessments.filter((assessment) => assessment.score !== null);
  const completedMasking = masking.filter((policy) => policy.workflowStatus === "validated");
  const generatedAt = new Intl.DateTimeFormat("en-IN", { dateStyle: "full", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(new Date());

  return (
    <>
      <PageHeader
        eyebrow="Management report"
        title="Database security assurance report"
        description={`Generated ${generatedAt} for the currently visible tenant-scoped records.`}
        actions={<PrintReportButton />}
      />
      <RepositoryStatus meta={state.result.meta} />

      <Panel>
        <div className={styles.reportHero}>
          <div>
            <h2>Executive summary</h2>
            <p>This report separates automated collection from human decisions. A high score means the reviewed controls passed; it does not claim that every possible database-security control was tested.</p>
          </div>
          <div className={styles.reportScore}><strong>{assuranceScore === null ? "—" : assuranceScore}</strong><span>{assuranceScore === null ? "Not scored" : "Assurance score /100"}</span></div>
        </div>
      </Panel>

      <section className={styles.metricGrid} aria-label="Report summary">
        <MetricCard label="Assets" value={String(assets.length)} helper="visible managed databases" icon={Database} />
        <MetricCard label="Completed assessments" value={String(completedAssessments.length)} helper={`${assessments.length} assessment records visible`} icon={ShieldCheck} />
        <MetricCard label="Open findings" value={String(unresolvedFindings.length)} helper="requiring governance attention" tone={unresolvedFindings.length ? "warning" : "good"} icon={TriangleAlert} />
        <MetricCard label="Evidence records" value={String(evidence.length)} helper="digest-backed records visible" icon={FileCheck2} />
      </section>

      <div className={styles.reportGrid}>
        <Panel>
          <SectionHeader title="Score interpretation" description="How the displayed result is calculated" />
          <div className={styles.reportBoundary}><strong>Assessment score = Passed ÷ (Passed + Failed) × 100.</strong><br />Controls marked Not applicable are excluded. Collected metadata is evidence, not an automatic pass. Only finalized human decisions contribute to a score.</div>
          <ul className={styles.reportList}>
            {overview.controlDomains.map((domain) => <li key={domain.name}><div><strong>{domain.name}</strong><span>{domain.controls} assessments · {domain.findings} findings</span></div><StatusPill status={domain.scoreAvailable ? domain.score >= 80 ? "Passed" : "Needs attention" : "Pending"} /></li>)}
          </ul>
        </Panel>

        <Panel>
          <SectionHeader title="Operating boundary" description="Database activity permitted by this local implementation" />
          <div className={styles.reportBoundary}>{getLocalMySqlMode() ? "The assurance collector reads approved metadata from local insurance_sample using a read-only account. The dedicated masker can write only to separate, server-derived local masked targets. Azure SQL is not used by this local workflow." : "The console is not running in the local MySQL mode; review the configured deployment boundary before relying on this report."}</div>
          <p className={styles.reportFootnote}>Raw customer values are not stored in the Hub evidence library. Workflow notes must not contain passwords, connection strings, or customer data.</p>
        </Panel>

        <Panel>
          <SectionHeader title="Priority findings" description="Unresolved findings visible to this report" />
          {unresolvedFindings.length ? <ul className={styles.reportList}>{unresolvedFindings.slice(0, 10).map((finding) => <li key={finding.id}><div><strong>{finding.title}</strong><span>{finding.asset} · owner: {finding.owner}</span></div><small>{finding.severity} · {finding.status}</small></li>)}</ul> : <p className={styles.reportFootnote}>No unresolved findings are visible.</p>}
        </Panel>

        <Panel>
          <SectionHeader title="Masking workflow outcomes" description="Separate local masked-copy governance records" />
          {completedMasking.length ? <ul className={styles.reportList}>{completedMasking.slice(0, 10).map((policy) => <li key={policy.id}><div><strong>{policy.name}</strong><span>{policy.sourceDatabase ?? "source"} → {policy.targetDatabase ?? "target"} · {policy.rowsCopied ?? 0} rows · {policy.columnsMasked ?? 0} columns</span></div><StatusPill status={policy.status} /></li>)}</ul> : <p className={styles.reportFootnote}>No human-validated masking workflow is visible.</p>}
        </Panel>
      </div>

      <Panel>
        <SectionHeader title="Evidence and limitations" description="What a reviewer should understand before sharing this report" />
        <ul className={styles.reportList}>
          <li><div><strong>Evidence provenance</strong><span>{evidence.length} visible records include control identifiers, timestamps, sources, retention labels, and recorded digests.</span></div></li>
          <li><div><strong>Human accountability</strong><span>Analyst rationales and finalization determine pass/fail scores; the collector does not make governance decisions.</span></div></li>
          <li><div><strong>Scope limitation</strong><span>This is a controlled local assurance implementation, not a certification or proof that every database threat has been eliminated.</span></div></li>
        </ul>
      </Panel>
    </>
  );
}
