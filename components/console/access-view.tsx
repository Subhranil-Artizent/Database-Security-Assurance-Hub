import { KeyRound, ShieldAlert, ShieldCheck, UserRoundCheck } from "lucide-react";
import { getConsoleDataMode, getConsoleRepository, loadConsoleData } from "./repository";
import {
  ActionNotice,
  DataUnavailable,
  EmptyState,
  MetricCard,
  PageHeader,
  PaginationNav,
  Panel,
  PlatformBadge,
  RepositoryStatus,
  SectionHeader,
  SeverityPill,
  StatusPill,
  TableFrame,
} from "./primitives";
import styles from "./console.module.css";

export interface AccessFilters {
  cursor?: string;
  notice?: string;
  error?: string;
}

export async function AccessView({ filters }: { filters: AccessFilters }) {
  const state = await loadConsoleData(() => getConsoleRepository().getAccessReviews({ cursor: filters.cursor, limit: 25 }));
  const live = getConsoleDataMode() === "api";
  if (state.status === "error") {
    return (
      <>
        <PageHeader eyebrow="Identity assurance" title="Local MySQL access security" description="Verify that the collector account remains read-only and record an accountable review decision." />
        <ActionNotice notice={filters.notice} error={filters.error} />
        <DataUnavailable state={state} />
      </>
    );
  }

  const accessReviews = state.result.value.items;
  const approved = accessReviews.filter((review) => review.reviewStatus === "Approved").length;
  const needsAttention = accessReviews.filter((review) => ["Critical", "High", "Medium"].includes(review.risk) && review.reviewStatus !== "Approved").length;
  const serviceAccounts = accessReviews.filter((review) => review.principalType === "Service account").length;

  return (
    <>
      <PageHeader eyebrow="Identity assurance" title="Local MySQL access security" description="Verify that the collector account remains read-only and record an accountable review decision." />
      <ActionNotice notice={filters.notice} error={filters.error} />
      <RepositoryStatus meta={state.result.meta} />

      <div className={styles.insightStrip} role="note">
        <ShieldCheck size={20} aria-hidden="true" />
        <div>
          <strong>Scope: local collector account only</strong>
          <span>The check reads the current MySQL account and its schema grants with allowlisted SELECT queries. Application users are not scanned, and no privileges are changed.</span>
        </div>
      </div>

      <section className={styles.metricGrid} aria-label="Access security summary">
        <MetricCard label="Accounts checked" value={String(accessReviews.length)} helper="collector identities on this page" icon={UserRoundCheck} />
        <MetricCard label="Verified read-only" value={String(approved)} helper="latest completed verification" tone="good" icon={ShieldCheck} />
        <MetricCard label="Needs attention" value={String(needsAttention)} helper="incomplete or excessive grants" tone={needsAttention ? "warning" : "good"} icon={ShieldAlert} />
        <MetricCard label="Service accounts" value={String(serviceAccounts)} helper="within the approved scan scope" icon={KeyRound} />
      </section>

      <Panel>
        <SectionHeader title="Collector-account verification" description="Evidence is refreshed automatically by the local read-only collector." />
        {accessReviews.length ? (
          <TableFrame label="Local MySQL collector access reviews">
            <table className={styles.dataTable}>
              <thead><tr><th>Account</th><th>Database</th><th>Effective grants</th><th>Risk</th><th>Checked</th><th>Status</th><th>Recommendation</th></tr></thead>
              <tbody>
                {accessReviews.map((review) => (
                  <tr key={review.id}>
                    <td><div className={styles.primaryCell}><strong>{review.principal}</strong><span>{review.principalType}</span></div></td>
                    <td><div className={styles.stackedCell}><PlatformBadge platform={review.platform} /><small>{review.asset}</small></div></td>
                    <td><code className={styles.permissionCode}>{review.access}</code></td>
                    <td><SeverityPill severity={review.risk} /></td>
                    <td className={styles.mutedCell}>{review.checkedAt ?? "Not checked"}</td>
                    <td>{review.reviewStatus ? <StatusPill status={review.reviewStatus} /> : null}</td>
                    <td className={styles.recommendationCell}>{review.recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableFrame>
        ) : (
          <EmptyState title="Verification is being prepared" message="Restart the local stack once to queue the first collector-account check. The page will populate after the read-only job completes." />
        )}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/access" />
      </Panel>

      {accessReviews.length ? (
        <Panel className={styles.actionPanel}>
          <SectionHeader title="Record an analyst decision" description="This updates only the Hub review record; it does not change grants in MySQL." />
          <form className={styles.actionForm} action="/console/actions/access-reviews" method="post" aria-label="Update an access review">
            <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
            <label className={styles.formField}>
              <span>Review</span>
              <select name="review_id" required disabled={!live}>
                {accessReviews.map((review) => <option key={review.id} value={review.id}>{review.principal} · {review.asset}</option>)}
              </select>
            </label>
            <label className={styles.formField}>
              <span>Decision</span>
              <select name="status" required disabled={!live} defaultValue="approved">
                <option value="approved">Approve current access</option>
                <option value="remediation_required">Remediation required</option>
                <option value="closed">Close review</option>
              </select>
            </label>
            <label className={styles.formField}>
              <span>Reason</span>
              <input name="reason" required minLength={3} maxLength={1000} placeholder="Explain the decision" disabled={!live} />
            </label>
            <div className={styles.formActions}><button className={styles.formSubmit} type="submit" disabled={!live}>Save decision</button></div>
            <p className={styles.formHint}>Automated verification remains evidence-based. A manual decision cannot grant or revoke database access.</p>
          </form>
        </Panel>
      ) : null}
    </>
  );
}
