import { Database, Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { getConsoleDataMode, getConsoleRepository, getLocalMySqlMode, loadConsoleData } from "./repository";
import { ActionNotice, DataUnavailable, FilterBar, FilterField, MetricCard, NoResults, PageHeader, PaginationNav, Panel, PlatformBadge, Progress, RepositoryStatus, SectionHeader, StatusPill, TableFrame } from "./primitives";
import styles from "./console.module.css";

export interface AssetFilters {
  q?: string;
  platform?: string;
  environment?: string;
  health?: string;
  cursor?: string;
  notice?: string;
  error?: string;
}

export async function AssetsView({ filters }: { filters: AssetFilters }) {
  const state = await loadConsoleData(() => getConsoleRepository().getAssets({ cursor: filters.cursor, limit: 25 }));
  const live = getConsoleDataMode() === "api";
  const localMySql = getLocalMySqlMode();
  if (state.status === "error") {
    return (
      <>
        <PageHeader eyebrow="Estate inventory" title="Database assets" description="Authoritative inventory, ownership, business context, and assurance posture for every connected database." />
        <ActionNotice notice={filters.notice} error={filters.error} />
        <DataUnavailable state={state} />
      </>
    );
  }

  const assets = state.result.value.items;
  const query = filters.q?.trim().toLowerCase() ?? "";
  const filteredAssets = assets.filter((asset) => {
    const matchesQuery = !query || [asset.name, asset.id, asset.owner, asset.businessService].some((value) => value.toLowerCase().includes(query));
    const matchesPlatform = !filters.platform || filters.platform === "all" || asset.platform === filters.platform;
    const matchesEnvironment = !filters.environment || filters.environment === "all" || asset.environment === filters.environment;
    const matchesHealth = !filters.health || filters.health === "all" || asset.health === filters.health;
    return matchesQuery && matchesPlatform && matchesEnvironment && matchesHealth;
  });

  return (
    <>
      <PageHeader eyebrow="Estate inventory" title="Database assets" description="Authoritative inventory, ownership, business context, and assurance posture for every connected database." />
      <ActionNotice notice={filters.notice} error={filters.error} />
      <RepositoryStatus meta={state.result.meta} />
      <section className={styles.metricGridThree} aria-label="Asset inventory summary">
        <MetricCard label="Assets on this page" value={String(assets.length)} helper={state.result.value.nextCursor ? "more assets available" : "end of inventory"} icon={Database} />
        <MetricCard label="Healthy posture" value={String(assets.filter((asset) => asset.health === "Healthy").length)} helper="based on latest synchronized state" tone="good" icon={ShieldCheck} />
        <MetricCard label="Needs intervention" value={String(assets.filter((asset) => asset.health !== "Healthy").length)} helper="attention, critical, or offline" tone="warning" icon={TriangleAlert} />
      </section>

      <Panel className={styles.actionPanel}>
        <SectionHeader
          title={localMySql ? "Local MySQL asset" : "Register database metadata"}
          description={localMySql ? "insurance_sample is registered automatically when the local stack starts." : live ? "Add a database inventory record. Credentials are never accepted by this form." : "Connect the live API to persist database inventory records."}
        />
        {localMySql ? (
          <div className={styles.insightStrip} role="note">
            <ShieldCheck size={20} aria-hidden="true" />
            <div><strong>No connection form is needed</strong><span>Host, username, and password stay in the local .env file. This page never accepts credentials and never writes to MySQL.</span></div>
          </div>
        ) : <form className={styles.actionForm} action="/console/actions/assets" method="post" aria-label="Register a database asset">
          <input type="hidden" name="operation_id" value={crypto.randomUUID()} />
          <label className={styles.formField}><span>CMDB identifier</span><input name="external_id" required maxLength={128} placeholder="cmdb-oracle-001" disabled={!live} /></label>
          <label className={styles.formField}><span>Database name</span><input name="name" required maxLength={160} placeholder="Finance Oracle" disabled={!live} /></label>
          <label className={styles.formField}><span>Platform</span><select name="platform" required disabled={!live}><option value="oracle">Oracle</option><option value="postgresql">PostgreSQL</option><option value="sybase">Sybase ASE</option><option value="mysql">MySQL</option></select></label>
          <label className={styles.formField}><span>Version</span><input name="version" required maxLength={80} placeholder="19c" disabled={!live} /></label>
          <label className={styles.formField}><span>Edition (optional)</span><input name="edition" maxLength={120} placeholder="Enterprise" disabled={!live} /></label>
          <label className={styles.formField}><span>Environment</span><select name="environment" required disabled={!live}><option value="production">Production</option><option value="staging">Staging</option><option value="test">Test</option><option value="development">Development</option><option value="disaster_recovery">Disaster recovery</option></select></label>
          <label className={styles.formField}><span>Accountable owner</span><input name="owner" required maxLength={160} placeholder="Database Engineering" disabled={!live} /></label>
          <label className={styles.formField}><span>Criticality</span><select name="criticality" required disabled={!live}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
          <p className={styles.formHint}>Only non-secret inventory metadata is saved. Database endpoints and credentials are configured outside this form.</p>
          <div className={styles.formActions}><button className={styles.formSubmit} type="submit" disabled={!live}>Register asset</button></div>
        </form>}
      </Panel>

      <Panel>
        <SectionHeader title="Managed database estate" description={`${filteredAssets.length} assets match on this page · synchronized from collector inventory`} />
        <form action="/console/assets" method="get" aria-label="Filter database assets">
          <FilterBar>
            <label className={styles.searchField}>
              <span className={styles.srOnly}>Search assets</span>
              <Search size={15} aria-hidden="true" />
              <input type="search" name="q" placeholder="Search asset, owner, service…" defaultValue={filters.q} />
            </label>
            <FilterField label="Platform" name="platform" defaultValue={filters.platform}>
              <option value="all">All platforms</option><option>Oracle</option><option>PostgreSQL</option><option>Sybase ASE</option><option>MySQL</option>
            </FilterField>
            <FilterField label="Environment" name="environment" defaultValue={filters.environment}>
              <option value="all">All environments</option><option>Production</option><option>Pre-production</option><option>Development</option>
            </FilterField>
            <FilterField label="Health" name="health" defaultValue={filters.health}>
              <option value="all">All health states</option><option>Healthy</option><option>Attention</option><option>Critical</option><option>Offline</option>
            </FilterField>
            <button className={styles.filterButton} type="submit">Apply filters</button>
          </FilterBar>
        </form>
        {filteredAssets.length ? (
          <TableFrame label="Database asset inventory">
            <table className={styles.dataTable}>
              <thead><tr><th>Database asset</th><th>Platform</th><th>Environment</th><th>Owner &amp; service</th><th>Coverage</th><th>Last scan</th><th>Health</th></tr></thead>
              <tbody>
                {filteredAssets.map((asset) => (
                  <tr key={asset.id}>
                    <td><div className={styles.primaryCell}><strong>{asset.name}</strong><span>{asset.id} · {asset.region}</span></div></td>
                    <td><div className={styles.stackedCell}><PlatformBadge platform={asset.platform} /><small>{asset.version}</small></div></td>
                    <td><span className={styles.environmentBadge}>{asset.environment}</span></td>
                    <td><div className={styles.primaryCell}><strong>{asset.owner}</strong><span>{asset.businessService}</span></div></td>
                    <td><Progress value={asset.controlCoverage} tone={asset.controlCoverage < 70 ? "warning" : "good"} /></td>
                    <td className={styles.mutedCell}>{asset.lastScan}</td>
                    <td><StatusPill status={asset.health} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableFrame>
        ) : <NoResults message="No database assets match the selected filters." />}
        <PaginationNav nextCursor={state.result.value.nextCursor} pathname="/console/assets" params={filters} />
      </Panel>
    </>
  );
}
