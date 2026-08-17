import { CircleCheckBig, Clock3, FileCheck2, ShieldAlert } from "lucide-react";
import { getConsoleDataMode, getConsoleRepository, getLocalSyntheticCollectionMode, loadConsoleData } from "./repository";
import { ActionNotice, DataUnavailable, EmptyState, FilterBar, FilterField, MetricCard, NoResults, PageHeader, PaginationNav, Panel, PlatformBadge, Progress, RepositoryStatus, ScoreRing, SecondaryLink, SectionHeader, StatusPill, TableFrame } from "./primitives";
import styles from "./console.module.css";

export interface AssessmentFilters {
  domain?: string;
  platform?: string;
  status?: string;
  cursor?: string;
  notice?: string;
  error?: string;
}

export async function AssessmentsView({ filters }: { filters: AssessmentFilters }) {
  const repository = getConsoleRepository();
  const [state, actionOptionsState] = await Promise.all([
    loadConsoleData(() => repository.getAssessments({ cursor: filters.cursor, limit: 25 })),
    loadConsoleData(() => repository.getAssessmentActionOptions()),
  ]);
  const live = getConsoleDataMode() === "api";
  const syntheticCollection = getLocalSyntheticCollectionMode();
  if (state.status === "error") {
    return (
      <>
        <PageHeader eyebrow="Control assurance" title="Assessments" description="Versioned, repeatable control evaluations with traceable evidence across every supported database platform." />
        <ActionNotice notice={filters.notice} error={filters.error} syntheticCollection={syntheticCollection} />
        <DataUnavailable state={state} />
      </>
    );
  }

  const assessments = state.result.value.items;
  const filtered = assessments.filter((assessment) => {
    const domain = !filters.domain || filters.domain === "all" || assessment.domain === filters.domain;
    const platform = !filters.platform || filters.platform === "all" || assessment.platform === filters.platform || assessment.platform === "All platforms";
    const status = !filters.status || filters.status === "all" || assessment.status === filters.status;
    return domain && platform && status;
  });
  const actionOptions = actionOptionsState.status === "ready" ? actionOptionsState.result.value : null;
  const actionReady = live && actionOptions !== null && actionOptions.targets.length > 0;
  const mysqlAssessments = assessments.filter((assessment) => assessment.platform === "MySQL");
  const latestMySql = mysqlAssessments.at(-1);
  const mysqlAssetName = actionOptions?.targets.find((target) => target.platform === "MySQL")?.assetName ?? "MySQL database";
  const automatedControls = latestMySql?.automatedControls ?? 0;
  const manualControls = latestMySql?.manualControlsPending ?? 0;
  const collectionErrors = latestMySql?.collectionErrors ?? 0;
  const mysqlCollectionComplete = latestMySql?.collectionStatus === "review_required" && collectionErrors === 0;
  const mysqlReviewFinalized = latestMySql?.score !== null;
  const totalResults = assessments.reduce((total, assessment) => total + assessment.passed + assessment.warnings + assessment.failed, 0);
  const totalPassed = assessments.reduce((total, assessment) => total + assessment.passed, 0);
  const totalEvidence = assessments.reduce((total, assessment) => total + assessment.evidence, 0);
  const scoredAssessments = assessments.filter(
    (assessment): assessment is typeof assessment & { score: number } => assessment.score !== null,
  );

  return (
    <>
      <PageHeader eyebrow="Control assurance" title="Assessments" description="Versioned, repeatable control evaluations with traceable evidence across every supported database platform." />
      <ActionNotice notice={filters.notice} error={filters.error} syntheticCollection={syntheticCollection} />
      <RepositoryStatus meta={state.result.meta} />
      <section className={styles.metricGrid} aria-label="Assessment summary">
        {latestMySql && !syntheticCollection ? (
          <>
            <MetricCard label="MySQL assessment runs" value={String(mysqlAssessments.length)} helper={`for ${mysqlAssetName}`} icon={CircleCheckBig} />
            <MetricCard label="Automatic collection" value={`${latestMySql.evidence}/${automatedControls || 3}`} helper={mysqlCollectionComplete ? "metadata collection complete" : "collection in progress"} tone="good" icon={FileCheck2} />
            <MetricCard label="Manual review" value={mysqlReviewFinalized ? "Complete" : String(manualControls)} helper={mysqlReviewFinalized ? "analyst decisions finalized" : "controls still requiring a decision"} tone={mysqlReviewFinalized ? "good" : "warning"} icon={ShieldAlert} />
            <MetricCard label="Collection errors" value={String(collectionErrors)} helper={collectionErrors ? "collector errors need investigation" : "no collector errors"} icon={CircleCheckBig} />
          </>
        ) : (
          <>
            <MetricCard label="Controls evaluated" value={String(totalResults)} helper="on this page" icon={CircleCheckBig} />
            <MetricCard label="Controls passed" value={String(totalPassed)} helper={totalResults ? `${Math.round((totalPassed / totalResults) * 100)}% effective coverage` : "awaiting completed results"} tone="good" icon={CircleCheckBig} />
            <MetricCard label="Exceptions" value={String(assessments.reduce((total, assessment) => total + assessment.warnings + assessment.failed, 0))} helper="review or remediation required" tone="warning" icon={ShieldAlert} />
            <MetricCard label="Evidence objects" value={String(totalEvidence)} helper="linked to visible assessments" icon={FileCheck2} />
          </>
        )}
      </section>

      <Panel className={styles.actionPanel}>
        <SectionHeader
          title={syntheticCollection ? "Run a synthetic local assessment" : "Run a database assessment"}
          description={
            syntheticCollection
              ? "Exercise the real queue, fencing, evidence, and review contracts without querying a customer database."
              : live
                ? "Create an idempotent assessment and queue an allowlisted collector job."
                : "Connect the live API to initiate collector work."
          }
        />
        {live && actionOptionsState.status === "error" ? (
          <DataUnavailable state={actionOptionsState} />
        ) : actionReady && actionOptions ? (
          <form className={`${styles.actionForm} ${styles.actionFormWide}`} action="/console/actions/assessments" method="post" aria-label="Run a database security assessment">
            <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
            <label className={styles.formField}>
              <span>Assessment target</span>
              <select name="assessment_target" required>
                {actionOptions.targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.assetName} · {target.platform} · {target.connectorName} · {target.controlPackTitle} v{target.controlPackVersion}
                  </option>
                ))}
              </select>
            </label>
            <p className={styles.formHint}>
              {syntheticCollection
                ? "Development only: deterministic metadata is generated locally, no source connection is opened, and the assessment stops at analyst review required without a score."
                : "The server selects approved read-only probes for the asset platform. The browser cannot submit SQL, database endpoints, or credentials."}
            </p>
            <div className={styles.formActions}><button className={styles.formSubmit} type="submit">{syntheticCollection ? "Queue synthetic collection" : "Queue assessment"}</button></div>
          </form>
        ) : (
          <EmptyState title={live ? "Valid assessment target required" : "Live action disabled in demo mode"} message={live ? "Register an asset with its online private collector, then publish an active immutable control pack for the same database platform." : "Local fixtures are read-only and cannot queue database work."} />
        )}
      </Panel>

      {latestMySql && !syntheticCollection ? (
        <Panel className={styles.plainResultPanel}>
          <div className={styles.plainResultHeader}>
            <div>
              <span className={styles.panelKicker}>Plain-language result</span>
              <h2>{mysqlAssetName}</h2>
              <p>
                {mysqlReviewFinalized
                  ? `The analyst review is finalized with a server-calculated score of ${latestMySql.score}/100.`
                  : mysqlCollectionComplete
                  ? "The read-only collector completed successfully. The result is waiting for a person to review the evidence; it is not a failed assessment."
                  : "The read-only metadata collection is still running. Refresh this page in a moment to see the completed evidence."}
              </p>
            </div>
            <StatusPill status={latestMySql.status} />
          </div>
          <div className={styles.plainResultGrid}>
            <article>
              <strong>Automatic evidence</strong>
              <b>{latestMySql.evidence} of {automatedControls || 3} collected</b>
              <span>Transport security, database object inventory, and collector account context.</span>
            </article>
            <article>
              <strong>Manual item</strong>
              <b>{mysqlReviewFinalized ? "Decision recorded" : `${manualControls || (mysqlCollectionComplete ? 1 : 0)} review pending`}</b>
              <span>The local masking-copy proof remains a human-reviewed control; it is never passed automatically.</span>
            </article>
            <article>
              <strong>Security score</strong>
              <b>{mysqlReviewFinalized ? `${latestMySql.score}/100` : "Not assigned yet"}</b>
              <span>{mysqlReviewFinalized ? "Calculated and stored by the assurance API." : "A score appears only after an authorized reviewer makes every control decision."}</span>
            </article>
          </div>
          <div className={styles.plainResultFooter}>
            <p><strong>Important:</strong> collected evidence is not a pass. Only the recorded analyst decisions determine the score.</p>
            <div className={styles.formActions}>
              <SecondaryLink href={`/console/assessments/${encodeURIComponent(latestMySql.id)}`}>Review controls</SecondaryLink>
              <SecondaryLink href="/console/evidence">View {latestMySql.evidence} evidence {latestMySql.evidence === 1 ? "record" : "records"}</SecondaryLink>
            </div>
          </div>
        </Panel>
      ) : null}

      {!latestMySql || scoredAssessments.length ? <div className={styles.assessmentSummaryGrid}>
        <Panel className={styles.scorePanel}>
          <div><span className={styles.panelKicker}>Page score</span><h2>Current assurance</h2><p>Average of completed, human-decided assessment scores visible on this page.</p></div>
          {scoredAssessments.length ? (
            <ScoreRing value={Math.round(scoredAssessments.reduce((sum, assessment) => sum + assessment.score, 0) / scoredAssessments.length)} size="large" />
          ) : (
            <span className={styles.mutedCell}>Not scored</span>
          )}
        </Panel>
        <Panel className={styles.schedulePanel}>
          <Clock3 size={21} aria-hidden="true" />
          <div><span className={styles.panelKicker}>Collection execution</span><h2>Durable job queue</h2><p>Leased work uses bounded retries, fencing, and idempotency keys.</p></div>
          <StatusPill status={actionOptions?.connectors.some((connector) => connector.status === "Online") ? "Online" : "Offline"} />
        </Panel>
      </div> : null}

      <Panel>
        <SectionHeader title="Assessment runs" description={`${filtered.length} assessments match on this page`} />
        <form action="/console/assessments" method="get" aria-label="Filter assessment control packs">
          <FilterBar>
            <FilterField label="Control domain" name="domain" defaultValue={filters.domain}>
              <option value="all">All control domains</option><option>Encryption</option><option>Data protection</option><option>Access security</option><option>Data masking</option>
            </FilterField>
            <FilterField label="Platform" name="platform" defaultValue={filters.platform}>
              <option value="all">All platforms</option><option>Oracle</option><option>PostgreSQL</option><option>Sybase ASE</option><option>MySQL</option>
            </FilterField>
            <FilterField label="Result" name="status" defaultValue={filters.status}>
              <option value="all">All results</option><option>Pending</option><option>Passed</option><option>Needs attention</option><option>Failed</option><option>Superseded</option>
            </FilterField>
            <button className={styles.filterButton} type="submit">Apply filters</button>
          </FilterBar>
        </form>
        {filtered.length ? (
          <TableFrame label="Assessment control packs">
            <table className={styles.dataTable}>
              <thead><tr><th>Assessment pack</th><th>Domain</th><th>Scope</th><th>Score</th><th>Collection / review</th><th>Automatic evidence</th><th>Last run</th><th>Status</th><th>Action</th></tr></thead>
              <tbody>
                {filtered.map((assessment) => {
                  const controlCount = assessment.controlCount ?? assessment.passed + assessment.warnings + assessment.failed;
                  const evidenceTarget = assessment.automatedControls || controlCount;
                  const awaitingReview = assessment.score === null && assessment.collectionStatus === "review_required";
                  return (
                    <tr key={assessment.id}>
                      <td><div className={styles.primaryCell}><strong>{assessment.name}</strong><span>{assessment.id}</span></div></td>
                      <td><span className={styles.domainBadge}>{assessment.domain}</span></td>
                      <td><PlatformBadge platform={assessment.platform} /></td>
                      <td>{assessment.score === null ? <span className={styles.mutedCell}>Not scored</span> : <ScoreRing value={assessment.score} size="small" />}</td>
                      <td>{awaitingReview ? <div className={styles.resultCounts}><span className={styles.passCount}>{assessment.evidence} collected</span><span className={styles.warnCount}>{assessment.manualControlsPending ?? 0} manual</span><span className={styles.failCount}>{assessment.collectionErrors ?? 0} errors</span></div> : <div className={styles.resultCounts}><span className={styles.passCount}>{assessment.passed} pass</span><span className={styles.warnCount}>{assessment.warnings} warn</span><span className={styles.failCount}>{assessment.failed} fail</span></div>}</td>
                      <td><Progress value={evidenceTarget ? Math.round((assessment.evidence / evidenceTarget) * 100) : 0} label={`${assessment.evidence} of ${evidenceTarget || 0}`} /></td>
                      <td className={styles.mutedCell}>{assessment.lastRun}</td>
                      <td><StatusPill status={assessment.status} /></td>
                      <td>
                        <SecondaryLink href={`/console/assessments/${encodeURIComponent(assessment.id)}`}>
                          {assessment.score === null ? "Review controls" : "View decisions"}
                        </SecondaryLink>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableFrame>
        ) : <NoResults message="No assessments match the selected filters." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/assessments" params={filters} />
      </Panel>
    </>
  );
}
