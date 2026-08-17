import type { ReactNode } from "react";
import Link from "next/link";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  CalendarDays,
  CircleAlert,
  ChevronRight,
  Download,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import type { ControlStatus, Health, Platform, Severity } from "./data";
import { platformClass } from "./data";
import type { ConsoleLoadState, RepositoryMeta } from "./repository";
import styles from "./console.module.css";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className={styles.pageHeader}>
      <div>
        <div className={styles.breadcrumb}>
          <Link href="/console">AegisDB</Link>
          <ChevronRight size={12} aria-hidden="true" />
          <span>{eyebrow}</span>
        </div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className={styles.pageActions}>{actions}</div> : null}
    </header>
  );
}

export function PrimaryLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className={styles.primaryButton}>
      {children}
      <ArrowRight size={15} aria-hidden="true" />
    </Link>
  );
}

export function SecondaryLink({ href, children, download = false }: { href: string; children: ReactNode; download?: boolean }) {
  return (
    <Link href={href} className={styles.secondaryButton} download={download}>
      {download ? <Download size={15} aria-hidden="true" /> : null}
      {children}
    </Link>
  );
}

export function MetricCard({
  label,
  value,
  helper,
  change,
  tone = "neutral",
  icon: Icon,
}: {
  label: string;
  value: string;
  helper: string;
  change?: number;
  tone?: "neutral" | "good" | "warning" | "critical";
  icon: LucideIcon;
}) {
  return (
    <article className={`${styles.metricCard} ${styles[tone]}`}>
      <div className={styles.metricTop}>
        <span>{label}</span>
        <span className={styles.metricIcon}><Icon size={18} strokeWidth={1.8} aria-hidden="true" /></span>
      </div>
      <strong className={styles.metricValue}>{value}</strong>
      <div className={styles.metricFooter}>
        {typeof change === "number" ? (
          <span className={change >= 0 ? styles.positiveChange : styles.negativeChange}>
            {change >= 0 ? <ArrowUpRight size={13} aria-hidden="true" /> : <ArrowDownRight size={13} aria-hidden="true" />}
            {Math.abs(change)}%
          </span>
        ) : null}
        <small>{helper}</small>
      </div>
    </article>
  );
}

export function SectionHeader({ title, description, href, linkLabel }: { title: string; description?: string; href?: string; linkLabel?: string }) {
  return (
    <header className={styles.sectionHeader}>
      <div>
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {href && linkLabel ? (
        <Link href={href}>{linkLabel}<ArrowUpRight size={14} aria-hidden="true" /></Link>
      ) : null}
    </header>
  );
}

export function PlatformBadge({ platform }: { platform: Platform | "All platforms" }) {
  const short = platform === "PostgreSQL" ? "PG" : platform === "Sybase ASE" ? "ASE" : platform === "Oracle" ? "ORA" : platform === "MySQL" ? "MY" : "ALL";
  return (
    <span className={`${styles.platformBadge} ${styles[platformClass(platform)]}`}>
      <b aria-hidden="true">{short}</b>
      {platform}
    </span>
  );
}

export function StatusPill({ status }: { status: Health | ControlStatus | "Online" | "Degraded" | "Offline" | "Archived" | "Validated" | "Execution recorded" | "Approved" | "Pilot" | "Draft" | "Digest recorded" | "Missing digest" | "Pending" | "Open" | "In review" | "Remediation required" | "Closed" | "In remediation" | "Risk accepted" | "Resolved" | "False positive" }) {
  const good = ["Healthy", "Passed", "Online", "Validated", "Approved", "Digest recorded", "Resolved", "Closed", "False positive"].includes(status);
  const bad = ["Critical", "Failed", "Offline"].includes(status);
  const pending = ["Archived", "Execution recorded", "Pilot", "Draft", "Pending", "Superseded", "Open", "In review", "In remediation", "Risk accepted"].includes(status);
  const tone = good ? "statusGood" : bad ? "statusBad" : pending ? "statusPending" : "statusWarning";
  return <span className={`${styles.statusPill} ${styles[tone]}`}><i aria-hidden="true" />{status}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return <span className={`${styles.severityPill} ${styles[`severity${severity}`]}`}>{severity}</span>;
}

export function Progress({ value, tone = "good", label }: { value: number; tone?: "good" | "warning" | "critical"; label?: string }) {
  const normalizedValue = Math.max(0, Math.min(value, 100));

  return (
    <div className={styles.progressWrap}>
      <div className={styles.progressMeta}><span>{label}</span><strong>{normalizedValue}%</strong></div>
      <div
        className={styles.progressTrack}
        role="progressbar"
        aria-label={label ? `${label}, ${normalizedValue}%` : `${normalizedValue}% complete`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={normalizedValue}
      >
        <span aria-hidden="true" className={styles[tone]} style={{ width: `${normalizedValue}%` }} />
      </div>
    </div>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`${styles.panel} ${className}`}>{children}</section>;
}

export function TableFrame({ children, label }: { children: ReactNode; label: string }) {
  return <div className={styles.tableFrame} role="region" aria-label={label}>{children}</div>;
}

export function FilterBar({ children }: { children: ReactNode }) {
  return <div className={styles.filterBar}>{children}</div>;
}

export function FilterField({ label, name, defaultValue, children }: { label: string; name: string; defaultValue?: string; children: ReactNode }) {
  return (
    <label className={styles.filterField}>
      <span>{label}</span>
      <select name={name} defaultValue={defaultValue ?? "all"}>{children}</select>
    </label>
  );
}

export function DateChip({ children }: { children: ReactNode }) {
  return <span className={styles.dateChip}><CalendarDays size={13} aria-hidden="true" />{children}</span>;
}

export function ScoreRing({ value, size = "normal" }: { value: number; size?: "small" | "normal" | "large" }) {
  return (
    <div className={`${styles.scoreRing} ${styles[`score${size}`]}`} style={{ "--score": `${value * 3.6}deg` } as React.CSSProperties} role="img" aria-label={`Assurance score ${value} out of 100`}>
      <span><strong>{value}</strong><small>/100</small></span>
    </div>
  );
}

export function NoResults({ message }: { message: string }) {
  return <div className={styles.noResults}><p>{message}</p><Link href="?">Clear all filters</Link></div>;
}

export function RepositoryStatus({ meta }: { meta: RepositoryMeta }) {
  const fixture = meta.source === "development-fixture";
  const label = fixture ? "Development fixture" : meta.stale ? "Live data may be stale" : "Live API";
  return (
    <div className={`${styles.repositoryStatus} ${meta.stale ? styles.repositoryStale : ""}`} role={meta.stale ? "status" : undefined}>
      <span aria-hidden="true" />
      <strong>{label}</strong>
      <small>Updated {formatTimestamp(meta.fetchedAt)}</small>
      {meta.requestId ? <small>Request {meta.requestId.slice(0, 8)}</small> : null}
    </div>
  );
}

export function DataUnavailable({ state }: { state: Extract<ConsoleLoadState<unknown>, { status: "error" }> }) {
  return (
    <section className={`${styles.panel} ${styles.dataUnavailable}`} role="alert">
      <CircleAlert size={24} aria-hidden="true" />
      <div>
        <h2>{state.code === "configuration" ? "Live API connection required" : state.code === "unsupported" ? "Capability not enabled" : "Live data unavailable"}</h2>
        <p>{state.message}</p>
        {state.requestId ? <small>Support reference: {state.requestId}</small> : null}
      </div>
      {state.retryable ? <Link href="?"><RefreshCw size={14} aria-hidden="true" />Retry</Link> : null}
    </section>
  );
}

export function ActionNotice({
  notice,
  error,
  syntheticCollection = false,
}: {
  notice?: string;
  error?: string;
  syntheticCollection?: boolean;
}) {
  const successMessage = notice === "asset_registered"
    ? "Database asset registered successfully."
    : notice === "assessment_queued"
      ? syntheticCollection
        ? "Synthetic metadata collection queued. Refresh shortly to see evidence and the analyst-review-required state; no score will be assigned."
        : "Assessment and collector job queued successfully."
      : notice === "control_decision_saved"
        ? "Control decision saved. The assessment score is unchanged until finalization."
      : notice === "assessment_finalized"
        ? "Assessment finalized. The assurance API calculated and stored the score from the saved control decisions."
      : notice === "finding_updated"
        ? "Finding workflow updated successfully."
      : notice === "access_review_updated"
        ? "Access-review decision saved successfully."
      : notice === "masking_policy_created"
        ? "Draft masking policy created. No database values were changed."
      : notice === "masking_policy_approved"
        ? "Masking plan approved. Approval does not execute database changes."
      : notice === "masking_copy_queued"
        ? "The bounded local masking copy was queued. The source remains read-only; refresh to see the worker result."
      : notice === "masking_execution_recorded"
        ? "External masking execution evidence recorded."
      : notice === "masking_policy_validated"
        ? "Masking policy evidence marked as validated."
      : notice === "masking_policy_archived"
        ? "Completed masking workflow archived. Its audit evidence and target database were not deleted or changed."
      : null;
  const errorMessage = error === "demo_read_only"
    ? "This action requires a live assurance API connection."
    : error === "forbidden"
      ? "Your assigned role does not permit this action."
      : error === "invalid_input"
        ? "Review the submitted values and try again."
      : error === "csrf"
          ? "The request could not be verified. Refresh the page and try again."
        : error === "session_expired"
          ? "Your session expired. Sign in again, then repeat the action."
        : error === "conflict"
          ? "This record changed while you were working. Refresh the page and continue from its current step."
        : error === "service_unavailable"
          ? "The local assurance service is temporarily unavailable. Keep this page open, restart the local stack if needed, and try again."
        : error === "invalid_response"
          ? "The assurance service returned an unexpected response. Refresh once; if it continues, keep the request reference and contact support."
          : error
            ? "The operation could not be completed. Try again or contact support."
            : null;
  if (!successMessage && !errorMessage) return null;
  return (
    <div className={`${styles.actionNotice} ${errorMessage ? styles.actionNoticeError : styles.actionNoticeSuccess}`} role={errorMessage ? "alert" : "status"}>
      <span>{errorMessage ?? successMessage}</span>
      {syntheticCollection && notice === "assessment_queued" && !errorMessage ? (
        <Link href="/console/assessments">Refresh status</Link>
      ) : notice === "masking_copy_queued" && !errorMessage ? (
        <Link href="/console/masking">Refresh status</Link>
      ) : null}
    </div>
  );
}

export function PaginationNav({ nextCursor, pathname, params }: { nextCursor: string | null; pathname: string; params?: object }) {
  if (!nextCursor) return null;
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) if (typeof value === "string" && value && key !== "cursor") query.set(key, value);
  query.set("cursor", nextCursor);
  return (
    <nav className={styles.pagination} aria-label="Results pagination">
      <span>More results are available</span>
      <Link href={`${pathname}?${query.toString()}`}>Next page<ArrowRight size={14} aria-hidden="true" /></Link>
    </nav>
  );
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return <div className={styles.emptyState}><CircleAlert size={22} aria-hidden="true" /><div><h3>{title}</h3><p>{message}</p></div></div>;
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "recently";
  return new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(date);
}
