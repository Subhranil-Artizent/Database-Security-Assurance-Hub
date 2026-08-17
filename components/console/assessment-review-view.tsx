import {
  CircleCheckBig,
  CircleDashed,
  FileCheck2,
  ListChecks,
} from "lucide-react";

import type {
  AssessmentObservation,
  AssessmentReviewControl,
  ReviewOutcome,
} from "./data";
import {
  getConsoleRepository,
  loadConsoleData,
} from "./repository";
import {
  ActionNotice,
  DataUnavailable,
  MetricCard,
  PageHeader,
  Panel,
  PlatformBadge,
  Progress,
  RepositoryStatus,
  ScoreRing,
  SecondaryLink,
  SectionHeader,
  SeverityPill,
  StatusPill,
} from "./primitives";
import styles from "./console.module.css";

const outcomeLabels: Record<ReviewOutcome, string> = {
  passed: "Pass",
  failed: "Fail",
  not_applicable: "Not applicable",
};

export interface AssessmentReviewFilters {
  notice?: string;
  error?: string;
}

export async function AssessmentReviewView({
  assessmentId,
  filters,
}: {
  assessmentId: string;
  filters: AssessmentReviewFilters;
}) {
  const repository = getConsoleRepository();
  const state = await loadConsoleData(() => repository.getAssessmentReview(assessmentId));

  if (state.status === "error") {
    return (
      <>
        <PageHeader
          eyebrow="Assessment review"
          title="Assessment review"
          description="Review collected metadata, record one human decision per control, and finalize only when every required decision is complete."
          actions={<SecondaryLink href="/console/assessments">Back to assessments</SecondaryLink>}
        />
        <ActionNotice notice={filters.notice} error={filters.error} />
        <DataUnavailable state={state} />
      </>
    );
  }

  const review = state.result.value;
  const decisions = review.controls
    .map((control) => control.decision)
    .filter((decision) => decision !== null);
  const passed = decisions.filter((decision) => decision.outcome === "passed").length;
  const failed = decisions.filter((decision) => decision.outcome === "failed").length;
  const notApplicable = decisions.filter(
    (decision) => decision.outcome === "not_applicable",
  ).length;
  const applicable = passed + failed;
  const previewScore = review.readyToFinalize && applicable
    ? Math.round((passed / applicable) * 100)
    : null;
  const evidenceCount = review.controls.reduce(
    (total, control) => total + control.evidenceIds.length,
    0,
  );
  const remaining = Math.max(0, review.totalControls - review.decidedCount);
  const completed = review.assessment.score !== null;

  return (
    <>
      <PageHeader
        eyebrow="Assessment review"
        title={review.assetName}
        description={`${review.assessment.name} · Review the evidence and record a clear decision for every control.`}
        actions={<SecondaryLink href="/console/assessments">Back to assessments</SecondaryLink>}
      />
      <ActionNotice notice={filters.notice} error={filters.error} />
      <RepositoryStatus meta={state.result.meta} />

      <section className={styles.metricGrid} aria-label="Assessment review progress">
        <MetricCard
          label="Controls reviewed"
          value={`${review.decidedCount}/${review.totalControls}`}
          helper={remaining ? `${remaining} decisions remaining` : "all decisions recorded"}
          tone={remaining ? "warning" : "good"}
          icon={ListChecks}
        />
        <MetricCard
          label="Evidence records"
          value={String(evidenceCount)}
          helper="metadata linked to these controls"
          icon={FileCheck2}
        />
        <MetricCard
          label="Not applicable"
          value={String(notApplicable)}
          helper="excluded from the score denominator"
          icon={CircleDashed}
        />
        <MetricCard
          label="Final score"
          value={completed ? `${review.assessment.score}/100` : "Pending"}
          helper={completed ? "calculated by the assurance API" : "available after finalization"}
          tone={completed ? "good" : "neutral"}
          icon={CircleCheckBig}
        />
      </section>

      <Panel className={styles.reviewContextPanel}>
        <div>
          <span className={styles.panelKicker}>Review scope</span>
          <h2>{review.assessment.name}</h2>
          <p>
            This workflow updates assurance review records only. It does not run SQL or
            change data in the MySQL database.
          </p>
        </div>
        <div className={styles.reviewContextMeta}>
          <PlatformBadge platform={review.assessment.platform} />
          <StatusPill status={review.assessment.status} />
        </div>
        <Progress
          value={review.totalControls
            ? Math.round((review.decidedCount / review.totalControls) * 100)
            : 0}
          label={`${review.decidedCount} of ${review.totalControls} reviewed`}
        />
      </Panel>

      <Panel>
        <SectionHeader
          title="Control-by-control review"
          description="Collection results are evidence, not automatic pass or fail decisions. Save a rationale for every human decision."
        />
        <div className={styles.reviewControlList}>
          {review.controls.map((control, index) => (
            <ControlReviewCard
              key={control.definition.id}
              assessmentId={review.assessment.id}
              control={control}
              index={index + 1}
              locked={completed}
            />
          ))}
        </div>
      </Panel>

      <Panel className={styles.finalizePanel}>
        <div className={styles.finalizeSummary}>
          <div>
            <span className={styles.panelKicker}>Transparent scoring</span>
            <h2>{completed ? "Assessment finalized" : "Finalize assessment"}</h2>
            <p>
              Score = passed ÷ (passed + failed) × 100. Controls marked Not applicable
              are excluded. The assurance API calculates and stores the final score;
              the browser never submits one.
            </p>
          </div>
          {completed && review.assessment.score !== null ? (
            <ScoreRing value={review.assessment.score} size="normal" />
          ) : previewScore !== null ? (
            <div className={styles.scorePreview}>
              <strong>{previewScore}/100</strong>
              <span>decision preview</span>
            </div>
          ) : null}
        </div>

        <div className={styles.decisionTotals} aria-label="Decision totals">
          <span><strong>{passed}</strong> passed</span>
          <span><strong>{failed}</strong> failed</span>
          <span><strong>{notApplicable}</strong> not applicable</span>
          <span><strong>{remaining}</strong> remaining</span>
        </div>

        {!completed && review.blockingReasons.length ? (
          <div className={styles.blockingReasons} role="status">
            <strong>Before finalizing</strong>
            <ul>
              {review.blockingReasons.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
          </div>
        ) : null}

        {!completed ? (
          <form
            className={styles.finalizeForm}
            action="/console/actions/assessments/finalize"
            method="post"
            aria-label="Finalize assessment"
          >
            <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
            <input type="hidden" name="assessment_id" value={review.assessment.id} />
            <input type="hidden" name="confirmation" value="finalize" />
            <p>
              Finalization locks the current decisions and publishes the server-calculated result.
            </p>
            <button className={styles.formSubmit} type="submit" disabled={!review.readyToFinalize}>
              Finalize assessment
            </button>
          </form>
        ) : (
          <p className={styles.finalizedMessage}>
            Final decisions are locked. Review the evidence library for the supporting metadata.
          </p>
        )}
      </Panel>
    </>
  );
}

function ControlReviewCard({
  assessmentId,
  control,
  index,
  locked,
}: {
  assessmentId: string;
  control: AssessmentReviewControl;
  index: number;
  locked: boolean;
}) {
  const collection = control.collectionResult;
  const canDecide = !locked && control.allowedOutcomes.length > 0;

  return (
    <article className={styles.reviewControlCard}>
      <header className={styles.reviewControlHeader}>
        <div>
          <span className={styles.reviewControlNumber}>Control {index}</span>
          <h3>{control.definition.title}</h3>
          <p><code>{control.definition.controlId}</code> · {formatToken(control.definition.assessmentMode)}</p>
        </div>
        <div>
          <SeverityPill severity={control.definition.severity} />
          <DecisionBadge outcome={control.decision?.outcome ?? null} />
        </div>
      </header>

      <p className={styles.reviewObjective}>{control.definition.objective}</p>

      <div className={styles.reviewControlBody}>
        <section className={styles.reviewEvidence} aria-label={`${control.definition.title} evidence`}>
          <h4>Collected metadata</h4>
          {collection ? (
            <>
              <div className={styles.collectionStatus}>
                <span>{formatToken(collection.outcome)}</span>
                <strong>{collection.evidenceCount} evidence {collection.evidenceCount === 1 ? "record" : "records"}</strong>
              </div>
              <p>{collection.rationale}</p>
            </>
          ) : (
            <p>No automatic collection result is available for this control.</p>
          )}

          {control.evidenceIds.length ? (
            <details className={styles.reviewDetails}>
              <summary>Evidence identifiers ({control.evidenceIds.length})</summary>
              <ul>
                {control.evidenceIds.map((evidenceId) => <li key={evidenceId}><code>{evidenceId}</code></li>)}
              </ul>
              <SecondaryLink href={`/console/evidence?assessment_id=${encodeURIComponent(assessmentId)}&control_id=${encodeURIComponent(control.definition.controlId)}`}>Open this control&apos;s evidence</SecondaryLink>
            </details>
          ) : null}

          {control.observations.length ? (
            <details className={styles.reviewDetails}>
              <summary>Collector observations ({control.observations.length})</summary>
              <div className={styles.observationList}>
                {control.observations.map((observation, observationIndex) => (
                  <Observation key={`${control.definition.id}-${observationIndex}`} observation={observation} />
                ))}
              </div>
            </details>
          ) : null}

          {control.definition.manualEvidenceRequirements.length ? (
            <details className={styles.reviewDetails}>
              <summary>Manual evidence required</summary>
              <ul>
                {control.definition.manualEvidenceRequirements.map((requirement) => (
                  <li key={requirement}>{requirement}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </section>

        <section className={styles.reviewDecision} aria-label={`${control.definition.title} decision`}>
          <h4>Human decision</h4>
          {control.decision ? (
            <div className={styles.savedDecision}>
              <DecisionBadge outcome={control.decision.outcome} />
              <p>{control.decision.rationale}</p>
            </div>
          ) : (
            <p>No decision has been recorded.</p>
          )}

          {canDecide ? (
            <form action="/console/actions/assessments/control-decision" method="post">
              <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
              <input type="hidden" name="assessment_id" value={assessmentId} />
              <input type="hidden" name="control_definition_id" value={control.definition.id} />
              <label className={styles.formField}>
                <span>Outcome</span>
                <select name="outcome" required defaultValue={control.decision?.outcome ?? ""}>
                  {!control.decision ? <option value="" disabled>Select an outcome</option> : null}
                  {control.allowedOutcomes.map((outcome) => (
                    <option key={outcome} value={outcome}>{outcomeLabels[outcome]}</option>
                  ))}
                </select>
              </label>
              <label className={styles.formField}>
                <span>Rationale</span>
                <textarea
                  name="rationale"
                  required
                  minLength={10}
                  maxLength={2000}
                  defaultValue={control.decision?.rationale ?? ""}
                  placeholder="Explain why the evidence supports this decision."
                />
              </label>
              <button className={styles.formSubmit} type="submit">Save decision</button>
            </form>
          ) : (
            <p className={styles.lockedDecision}>
              {locked ? "This assessment is finalized; decisions are locked." : "This control is not currently open for a decision."}
            </p>
          )}
        </section>
      </div>

      <details className={styles.remediationDetails}>
        <summary>Remediation guidance</summary>
        <p>{control.definition.remediationGuidance}</p>
      </details>
    </article>
  );
}

function DecisionBadge({ outcome }: { outcome: ReviewOutcome | null }) {
  const label = outcome ? outcomeLabels[outcome] : "Awaiting decision";
  const tone = outcome === "passed"
    ? styles.reviewOutcomePassed
    : outcome === "failed"
      ? styles.reviewOutcomeFailed
      : outcome === "not_applicable"
        ? styles.reviewOutcomeNotApplicable
        : styles.reviewOutcomePending;
  return <span className={`${styles.reviewOutcome} ${tone}`}>{label}</span>;
}

function Observation({ observation }: { observation: AssessmentObservation }) {
  return (
    <dl>
      {Object.entries(observation).map(([key, value]) => (
        <div key={key}>
          <dt>{formatToken(key)}</dt>
          <dd>{value === null ? "Not reported" : typeof value === "boolean" ? value ? "Yes" : "No" : String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function formatToken(value: string): string {
  const label = value.replaceAll("_", " ").trim();
  return label ? `${label.charAt(0).toUpperCase()}${label.slice(1)}` : "Not reported";
}
