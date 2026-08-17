import { Cable, CircleCheckBig, CloudCog, RefreshCw, ServerCog, ShieldCheck, WifiOff } from "lucide-react";
import { getConsoleRepository, loadConsoleData } from "./repository";
import { DataUnavailable, EmptyState, MetricCard, PageHeader, PaginationNav, Panel, PlatformBadge, RepositoryStatus, SectionHeader, StatusPill } from "./primitives";
import styles from "./console.module.css";

export async function ConnectorsView({ cursor }: { cursor?: string }) {
  const state = await loadConsoleData(() => getConsoleRepository().getConnectors({ cursor, limit: 25 }));
  if (state.status === "error") return <><PageHeader eyebrow="Administration" title="Private collectors" description="Manage the outbound-only collection layer that evaluates database controls inside customer-controlled network boundaries." /><DataUnavailable state={state} /></>;
  const connectors = state.result.value.items;
  return (
    <>
      <PageHeader eyebrow="Administration" title="Private collectors" description="Manage the outbound-only collection layer that evaluates database controls inside customer-controlled network boundaries." />
      <RepositoryStatus meta={state.result.meta} />
      <section className={styles.metricGrid} aria-label="Collector summary">
        <MetricCard label="Registered collectors" value={String(connectors.length)} helper="visible on this page" icon={Cable} />
        <MetricCard label="Healthy" value={String(connectors.filter((connector) => connector.status === "Online").length)} helper="heartbeats inside service objective" tone="good" icon={CircleCheckBig} />
        <MetricCard label="Managed assets" value={String(connectors.reduce((sum, connector) => sum + connector.assets, 0))} helper="assigned collector targets" icon={ServerCog} />
        <MetricCard label="Recovery active" value={String(connectors.filter((connector) => connector.status === "Degraded").length)} helper="bounded retry or operator action" tone="warning" icon={RefreshCw} />
      </section>

      <div className={styles.connectorArchitecture}>
        <div><ServerCog size={20} aria-hidden="true" /><strong>Database estate</strong><span>Read-only service accounts</span></div>
        <i aria-hidden="true"><span>Allowlisted queries</span></i>
        <div><Cable size={20} aria-hidden="true" /><strong>Private collector</strong><span>Local execution boundary</span></div>
        <i aria-hidden="true"><span>Outbound mTLS</span></i>
        <div><CloudCog size={20} aria-hidden="true" /><strong>Assurance API</strong><span>Metadata and evidence only</span></div>
      </div>

      <Panel>
        <SectionHeader title="Collector fleet" description="Deployment inventory, heartbeat state, and recovery posture from the control plane." />
        {connectors.length ? <div className={styles.connectorGrid}>
          {connectors.map((connector) => (
            <article className={styles.connectorCard} key={connector.id}>
              <header>
                <span className={styles.connectorIcon}><Cable size={18} aria-hidden="true" /></span>
                <div><strong>{connector.name}</strong><small>{connector.id} · v{connector.version}</small></div>
                <StatusPill status={connector.status} />
              </header>
              <dl>
                <div><dt>Platform</dt><dd><PlatformBadge platform={connector.platform} /></dd></div>
                <div><dt>Network zone</dt><dd>{connector.region}</dd></div>
                <div><dt>Managed assets</dt><dd>{connector.assets}</dd></div>
                <div><dt>Last heartbeat</dt><dd>{connector.lastHeartbeat}</dd></div>
                <div><dt>Next collection</dt><dd>{connector.nextScan}</dd></div>
                <div><dt>Service account</dt><dd><code>{connector.serviceAccount}</code></dd></div>
              </dl>
              <footer><span>Release channel: {connector.releaseChannel}</span><span className={connector.status === "Online" ? styles.goodText : styles.warningText}>{connector.status === "Online" ? "Within SLO" : "Retry policy active"}</span></footer>
            </article>
          ))}
        </div> : <EmptyState title="No collectors registered" message="Complete an approved private collector onboarding before running assessments." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/admin/connectors" />
      </Panel>

      <Panel>
        <SectionHeader title="Collection safety controls" description="Required guardrails before a connector may evaluate a database" />
        <div className={styles.guardrailGrid}>
          <div><ShieldCheck size={18} aria-hidden="true" /><strong>Read-only identity</strong><span>No CREATE, UPDATE, DELETE, or administrative privileges.</span></div>
          <div><RefreshCw size={18} aria-hidden="true" /><strong>Bounded retries</strong><span>Exponential backoff, circuit breaking, and idempotency keys.</span></div>
          <div><ServerCog size={18} aria-hidden="true" /><strong>Workload limits</strong><span>Query timeouts, concurrency ceilings, and collection windows.</span></div>
          <div><WifiOff size={18} aria-hidden="true" /><strong>Outbound only</strong><span>No inbound network route from the assurance service.</span></div>
        </div>
      </Panel>
    </>
  );
}
