import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render(pathname = "/", requestHeaders = {}, requestInit = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${pathname}`, {
      ...requestInit,
      headers: { accept: "text/html", ...requestHeaders },
    }),
    {
      ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
    },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

const signedInHeaders = {
  "oai-authenticated-user-id": "test-user-001",
  "oai-authenticated-user-email": "security.architect@example.com",
  "oai-authenticated-user-full-name": "Security%20Architect",
  "oai-authenticated-user-full-name-encoding": "percent-encoded-utf-8",
};

function attributeValues(html, attribute) {
  const pattern = new RegExp(`\\b${attribute}=["']([^"']+)["']`, "gi");
  return [...html.matchAll(pattern)].map((match) => match[1]);
}

test("server-renders the finished AegisDB landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();

  assert.match(html, /<title>AegisDB \| Database Security Assurance<\/title>/i);
  assert.match(
    html,
    /<h1\b[^>]*>\s*Secure every database\.\s*<span>Protect every sensitive record\.<\/span>\s*<\/h1>/i,
  );

  for (const control of [
    "Database encryption",
    "Data protection",
    "Access security",
    "Data masking",
  ]) {
    assert.match(html, new RegExp(`<h3\\b[^>]*>\\s*${control}\\s*</h3>`, "i"));
  }

  for (const platform of ["Oracle", "PostgreSQL", "Sybase", "MySQL"]) {
    assert.match(html, new RegExp(`<h3\\b[^>]*>\\s*${platform}\\s*</h3>`, "i"));
  }

  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|sites-skeleton|Your site is taking shape/i);
});

test("protects and server-renders every assurance console route", async () => {
  const anonymous = await render("/console");
  assert.ok([302, 303, 307, 308].includes(anonymous.status));
  assert.match(
    anonymous.headers.get("location") ?? "",
    /^\/signin-with-chatgpt\?return_to=%2Fconsole$/,
  );

  const routes = new Map([
    ["/console", "Security assurance overview"],
    ["/console/assets", "Database assets"],
    ["/console/assessments", "Assessments"],
    ["/console/findings", "Security findings"],
    ["/console/data-discovery", "Sensitive-data discovery"],
    ["/console/access", "Local MySQL access security"],
    ["/console/masking", "Masking governance"],
    ["/console/evidence", "Evidence library"],
    ["/console/report", "Database security assurance report"],
    ["/console/admin/connectors", "Private collectors"],
  ]);

  for (const [route, heading] of routes) {
    const response = await render(route, signedInHeaders);
    assert.equal(response.status, 200, `${route} should render for an authenticated user`);
    const html = await response.text();
    assert.match(html, new RegExp(`<h1\\b[^>]*>\\s*${heading}\\s*</h1>`, "i"));
    assert.match(html, /Live control plane/i);
    assert.match(html, /Live API connection required|Capability not enabled/i);
    assert.doesNotMatch(html, /Representative read-only fixtures|Demo data/i);
    const escapedRoute = route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(
      html,
      new RegExp(`<a\\b(?=[^>]*\\bhref=["']${escapedRoute}["'])(?=[^>]*\\baria-current=["']page["'])[^>]*>`, "i"),
      `${route} should identify its current navigation item`,
    );
  }
});

test("gives the protected console keyboard and assistive-technology semantics", async () => {
  const response = await render("/console", signedInHeaders);
  assert.equal(response.status, 200);
  const html = await response.text();

  assert.match(html, /<a\b[^>]*href=["']#console-main["'][^>]*>\s*Skip to main content\s*<\/a>/i);
  assert.match(html, /<main\b(?=[^>]*\bid=["']console-main["'])(?=[^>]*\btabindex=["']-1["'])[^>]*>/i);
  assert.match(html, /<nav\b[^>]*\baria-label=["']Console navigation["']/i);
  assert.match(html, /role=["']alert["']/i);
  assert.match(html, /Live API connection required/i);
  assert.doesNotMatch(html, /<button\b[^>]*aria-label=["'](?:Notifications|Open profile menu)/i);
});

test("server-renders the protected assessment review route fail closed", async () => {
  const response = await render(
    "/console/assessments/11111111-1111-1111-1111-111111111111",
    signedInHeaders,
  );
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /<h1\b[^>]*>\s*Assessment review\s*<\/h1>/i);
  assert.match(html, /href=["']\/console\/assessments["'][^>]*>\s*Back to assessments/i);
  assert.match(html, /Live API connection required|Capability not enabled/i);
  assert.doesNotMatch(html, /name=["'](?:score|reviewer|source_endpoint|sql|password|credentials?)["']/i);
});

test("server-renders masking as a bounded local MySQL capability without browser overrides", async () => {
  const response = await render("/console/masking", signedInHeaders);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /<h1\b[^>]*>\s*Masking governance\s*<\/h1>/i);
  assert.match(html, /Create and verify a bounded masked copy in a separate local MySQL database/i);
  assert.match(html, /Live API connection required|Capability not enabled/i);
  assert.doesNotMatch(
    html,
    /name=["'](?:source_database|target_database|staging_database|row_cap|host|port|sql|password|credentials?)["']/i,
  );
  assert.doesNotMatch(html, /insurance_sample_masked_staging/i);
  assert.doesNotMatch(html, /database\.windows\.net/i);
});

test("fails console write actions closed and rejects cross-site form posts", async () => {
  const body = new URLSearchParams({
    operation_id: "operation-asset-0001",
    external_id: "cmdb-oracle-001",
    name: "Finance Oracle",
    platform: "oracle",
    version: "19c",
    edition: "Enterprise",
    environment: "production",
    owner: "Database Engineering",
    criticality: "critical",
  }).toString();
  const formHeaders = {
    "content-type": "application/x-www-form-urlencoded",
    "content-length": String(body.length),
    origin: "http://localhost",
    "sec-fetch-site": "same-origin",
  };

  const anonymous = await render("/console/actions/assets", formHeaders, { method: "POST", body });
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.headers.get("cache-control"), "no-store");

  const crossSite = await render(
    "/console/actions/assets",
    { ...signedInHeaders, ...formHeaders, origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    { method: "POST", body },
  );
  assert.equal(crossSite.status, 403);

  const missingServerConfig = await render(
    "/console/actions/assets",
    { ...signedInHeaders, ...formHeaders },
    { method: "POST", body },
  );
  assert.equal(missingServerConfig.status, 303);
  assert.match(missingServerConfig.headers.get("location") ?? "", /\/console\/assets\?error=demo_read_only$/);
});

test("keeps console text at an accessible minimum size", async () => {
  const css = await readFile(new URL("../components/console/console.module.css", import.meta.url), "utf8");
  assert.doesNotMatch(css, /font-size:\s*(?:[0-9]|10)px\b/);
});

test("adds health and browser security response headers", async () => {
  const response = await render("/");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/i);
  assert.match(response.headers.get("x-request-id") ?? "", /^[a-f0-9-]{36}$/i);

  const health = await render("/healthz");
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.equal((await health.json()).status, "ok");
});

test("rejects untrusted forwarded hosts when generating absolute metadata", async () => {
  const response = await render("/", {
    "x-forwarded-host": "attacker.example/path",
    "x-forwarded-proto": "javascript",
  });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.doesNotMatch(html, /attacker\.example|javascript:/i);
  assert.match(html, /http:\/\/localhost:3000\/og\.png/i);
});

test("provides working navigation and accessible semantic sections", async () => {
  const response = await render();
  const html = await response.text();
  const ids = new Set(attributeValues(html, "id"));
  const hrefs = attributeValues(html, "href");
  const fragmentTargets = hrefs.filter((href) => href.startsWith("#")).map((href) => href.slice(1));

  assert.deepEqual(
    new Set(fragmentTargets),
    new Set(["top", "capabilities", "platforms", "approach", "assessment"]),
  );
  assert.ok(fragmentTargets.length > new Set(fragmentTargets).size);
  for (const target of fragmentTargets) {
    assert.ok(target.length > 0, "in-page links must name a target");
    assert.ok(ids.has(target), `missing section id for href="#${target}"`);
  }
  assert.ok(
    hrefs.includes("/console/assessments"),
    "the assessment call to action should open the functional assessment page",
  );

  assert.match(html, /<html\b[^>]*\blang=["']en["']/i);
  assert.equal((html.match(/<main\b/gi) ?? []).length, 1);
  assert.match(html, /<header\b/i);
  assert.match(html, /<nav\b[^>]*\baria-label=["']Primary navigation["']/i);
  assert.match(html, /<h1\b[^>]*\bid=["']hero-title["']/i);

  const labelledSections = [
    ...html.matchAll(/<section\b[^>]*\baria-labelledby=["']([^"']+)["']/gi),
  ].map((match) => match[1]);
  assert.ok(labelledSections.length >= 5);
  for (const labelId of labelledSections) {
    assert.ok(ids.has(labelId), `section label id "${labelId}" must exist`);
  }
});
