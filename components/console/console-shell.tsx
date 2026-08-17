import type { ReactNode } from "react";
import Link from "next/link";
import {
  Activity,
  ChevronDown,
  Search,
  ShieldCheck,
} from "lucide-react";
import type { ChatGPTUser } from "@/app/chatgpt-auth";
import type { ConsoleDataMode } from "./repository";
import { ConsoleNavigation } from "./console-navigation";
import styles from "./console.module.css";

function Brand() {
  return (
    <Link className={styles.brand} href="/" aria-label="AegisDB home">
      <span className={styles.brandMark} aria-hidden="true">
        <ShieldCheck size={19} strokeWidth={1.8} />
      </span>
      <span>
        <strong>AegisDB</strong>
        <small>Assurance Hub</small>
      </span>
    </Link>
  );
}

function EnvironmentCard({
  dataMode,
  localMySql,
  syntheticCollection,
}: {
  dataMode: ConsoleDataMode;
  localMySql: boolean;
  syntheticCollection: boolean;
}) {
  const live = dataMode === "api";
  return (
    <div className={styles.environmentCard}>
      <div>
        <span className={styles.liveDot} aria-hidden="true" />
        <strong>
          {localMySql
            ? "Local MySQL"
            : syntheticCollection
            ? "Synthetic collector"
            : live
              ? "Live control plane"
              : "Local demonstration"}
        </strong>
      </div>
      <p>
        {localMySql
          ? "Read-only collector"
          : syntheticCollection
          ? "Local metadata only"
          : live
            ? "Server-authenticated API"
            : "Read-only fixture data"}
      </p>
      <Link href="/console/admin/connectors">View collector health</Link>
    </div>
  );
}

export function ConsoleShell({
  children,
  user,
  dataMode,
  localMySql,
  syntheticCollection,
}: {
  children: ReactNode;
  user: ChatGPTUser;
  dataMode: ConsoleDataMode;
  localMySql: boolean;
  syntheticCollection: boolean;
}) {
  const live = dataMode === "api";
  return (
    <div className={styles.console}>
      <a className={styles.skipLink} href="#console-main">Skip to main content</a>
      <aside className={styles.sidebar}>
        <Brand />
        <ConsoleNavigation />
        <EnvironmentCard dataMode={dataMode} localMySql={localMySql} syntheticCollection={syntheticCollection} />
      </aside>

      <div className={styles.workspace}>
        <header className={styles.topbar}>
          <details className={styles.mobileMenu}>
            <summary aria-label="Open navigation">
              <span className={styles.mobileMenuIcon} aria-hidden="true">•••</span>
              <span>Menu</span>
              <ChevronDown size={15} aria-hidden="true" />
            </summary>
            <div className={styles.mobileMenuPanel}>
              <Brand />
              <ConsoleNavigation />
            </div>
          </details>

          <form className={styles.globalSearch} action="/console/assets" method="get" role="search">
            <Search size={16} strokeWidth={1.8} aria-hidden="true" />
            <label className={styles.srOnly} htmlFor="console-global-search">Search database assets</label>
            <input id="console-global-search" name="q" type="search" placeholder="Search database assets…" autoComplete="off" />
          </form>

          <div className={styles.topbarActions}>
            <div
              className={styles.scanState}
              title={
                localMySql
                  ? "Local MySQL data from the read-only collector"
                  : syntheticCollection
                  ? "Development-only synthetic evidence; no database query is executed"
                  : live
                    ? "Live API data mode"
                    : "Local development fixtures are displayed"
              }
            >
              <Activity size={14} strokeWidth={2} aria-hidden="true" />
              <span>{localMySql ? "Local MySQL" : syntheticCollection ? "Synthetic data" : live ? "Live data" : "Demo data"}</span>
            </div>
            <div className={styles.profileIdentity} aria-label={`Signed in as ${user.email}`}>
              <span className={styles.avatar}>{user.displayName.slice(0, 2).toUpperCase()}</span>
              <span className={styles.profileText}>
                <strong>{user.fullName ?? user.displayName}</strong>
                <small>{user.email}</small>
              </span>
            </div>
          </div>
        </header>
        <main id="console-main" className={styles.main} tabIndex={-1}>
          <div
            className={styles.demoBanner}
            role="status"
            data-mode={localMySql ? "mysql" : syntheticCollection ? "synthetic" : dataMode}
          >
            <strong>
              {localMySql
                ? "Local MySQL · read-only source"
                : syntheticCollection
                ? "Synthetic local collection — no customer database queried"
                : live
                  ? "Live control plane"
                  : "Local demo mode"}
            </strong>
            <span>
              {localMySql
                ? "insurance_sample is queried only with approved SELECT metadata probes. The Hub never writes to the source database."
                : syntheticCollection
                ? "Submitted assessments create deterministic metadata evidence and stop at analyst review required with no score."
                : live
                  ? "Console records are requested server-side from the authenticated assurance API."
                  : "Representative read-only fixtures are shown. Inputs are enabled after connecting the live API."}
            </span>
          </div>
          {children}
        </main>
      </div>
    </div>
  );
}
