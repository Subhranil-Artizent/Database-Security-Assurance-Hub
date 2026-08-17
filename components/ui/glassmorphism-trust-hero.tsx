"use client";

import { useEffect } from "react";
import Link from "next/link";
import {
  ArrowDownRight,
  ArrowRight,
  Check,
  ChevronRight,
  CircleCheck,
  Database,
  EyeOff,
  Fingerprint,
  KeyRound,
  Layers3,
  LockKeyhole,
  Network,
  ScanSearch,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

const NAV_ITEMS = [
  { label: "Capabilities", href: "#capabilities" },
  { label: "Platforms", href: "#platforms" },
  { label: "Approach", href: "#approach" },
];

const CAPABILITIES = [
  {
    icon: LockKeyhole,
    number: "01",
    title: "Database encryption",
    description:
      "Protect data at rest and in transit, validate key ownership, and expose coverage gaps before they become findings.",
    tags: ["TDE", "TLS", "Key governance"],
  },
  {
    icon: ShieldCheck,
    number: "02",
    title: "Data protection",
    description:
      "Discover and classify sensitive records, map policy to technical controls, and retain evidence of enforcement.",
    tags: ["Discovery", "Classification", "Policy"],
  },
  {
    icon: Fingerprint,
    number: "03",
    title: "Access security",
    description:
      "Reduce standing privilege, govern administrative paths, and bring high-risk database activity into view.",
    tags: ["Least privilege", "PAM", "Monitoring"],
  },
  {
    icon: EyeOff,
    number: "04",
    title: "Data masking",
    description:
      "Keep production and non-production data useful without exposing real identities or sensitive values.",
    tags: ["Static", "Dynamic", "Test data"],
  },
];

const PLATFORMS = [
  {
    code: "ORA",
    title: "Oracle",
    description: "TDE, Database Vault, Data Safe, Audit Vault and Database Firewall.",
  },
  {
    code: "PG",
    title: "PostgreSQL",
    description: "TLS, pgcrypto, row-level security, pgaudit and role hardening.",
  },
  {
    code: "SYB",
    title: "Sybase",
    description: "Encrypted columns, SSL, granular roles and unified auditing.",
  },
  {
    code: "MY",
    title: "MySQL",
    description: "Transport controls, schema inventory, account context and read-only evidence.",
  },
];

const STEPS = [
  ["Discover", "Inventory databases, sensitive data, identities, and current controls."],
  ["Prioritize", "Translate exposure and business criticality into a sequenced roadmap."],
  ["Protect", "Implement platform-native and compensating controls with clear ownership."],
  ["Prove", "Continuously collect evidence and show measurable assurance coverage."],
];

const SCOPE_ITEMS = [
  { label: "Encryption", icon: KeyRound },
  { label: "Data protection", icon: ShieldCheck },
  { label: "Access security", icon: Fingerprint },
  { label: "Data masking", icon: EyeOff },
];

const PLATFORM_NAMES = ["Oracle", "PostgreSQL", "Sybase", "MySQL"];

export default function HeroSection() {
  useEffect(() => {
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const finePointer = window.matchMedia("(pointer: fine)");
    const root = document.documentElement;
    const revealTargets = Array.from(
      document.querySelectorAll<HTMLElement>(
        ".context-strip, .split-heading, .capability-card, .platform-intro, .platform-panel, .approach-heading, .step-card, .outcomes-copy, .outcomes-list > div, .assessment-section",
      ),
    );

    let observer: IntersectionObserver | undefined;
    let heroVisual: HTMLElement | null = null;
    let scopeStage: HTMLElement | null = null;

    if (!reducedMotion.matches) {
      revealTargets.forEach((target, index) => {
        target.classList.add("motion-item");
        target.style.setProperty("--reveal-delay", `${(index % 4) * 70}ms`);
      });
      root.classList.add("motion-ready");

      observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add("is-visible");
              observer?.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.12, rootMargin: "0px 0px -7% 0px" },
      );
      revealTargets.forEach((target) => observer?.observe(target));

      if (finePointer.matches) {
        heroVisual = document.querySelector<HTMLElement>(".hero-visual");
        scopeStage = document.querySelector<HTMLElement>(".scope-stage");
      }
    }

    const handlePointerMove = (event: PointerEvent) => {
      if (!heroVisual || !scopeStage) return;
      const bounds = heroVisual.getBoundingClientRect();
      const horizontal = (event.clientX - bounds.left) / bounds.width - 0.5;
      const vertical = (event.clientY - bounds.top) / bounds.height - 0.5;
      scopeStage.style.setProperty("--tilt-x", `${vertical * -4}deg`);
      scopeStage.style.setProperty("--tilt-y", `${horizontal * 5}deg`);
    };

    const resetPointerTilt = () => {
      scopeStage?.style.setProperty("--tilt-x", "0deg");
      scopeStage?.style.setProperty("--tilt-y", "0deg");
    };

    heroVisual?.addEventListener("pointermove", handlePointerMove);
    heroVisual?.addEventListener("pointerleave", resetPointerTilt);

    return () => {
      observer?.disconnect();
      heroVisual?.removeEventListener("pointermove", handlePointerMove);
      heroVisual?.removeEventListener("pointerleave", resetPointerTilt);
      root.classList.remove("motion-ready");
    };
  }, []);

  return (
    <main className="site-shell">
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />

      <header className="site-header">
        <a className="brand" href="#top" aria-label="AegisDB home">
          <span className="brand-mark" aria-hidden="true">
            <Database size={18} strokeWidth={1.9} />
          </span>
          <span>AegisDB</span>
        </a>
        <nav className="desktop-nav" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => (
            <a key={item.href} href={item.href}>{item.label}</a>
          ))}
        </nav>
        <a className="header-cta" href="/console">
          Open assurance hub <ArrowDownRight size={16} aria-hidden="true" />
        </a>
      </header>

      <section className="hero-section" id="top" aria-labelledby="hero-title">
        <div className="hero-copy">
          <div className="eyebrow reveal reveal-one">
            <span className="eyebrow-dot" aria-hidden="true" />
            Database security assurance
          </div>
          <h1 id="hero-title" className="hero-title reveal reveal-two">
            Secure every database.
            <span>Protect every sensitive record.</span>
          </h1>
          <p className="hero-description reveal reveal-three">
            A unified assurance approach for Oracle, PostgreSQL, Sybase, and MySQL—helping
            teams encrypt sensitive data, govern privileged access, mask
            non-production copies, and demonstrate control coverage.
          </p>
          <div className="hero-actions reveal reveal-four">
            <a className="button button-primary" href="#assessment">
              Plan a security assessment <ArrowRight size={17} aria-hidden="true" />
            </a>
            <a className="button button-secondary" href="#capabilities">
              Explore control coverage <ChevronRight size={17} aria-hidden="true" />
            </a>
          </div>
          <div className="scope-summary reveal reveal-five" aria-label="Assurance scope summary">
            <div><strong>1</strong><span>Unified assurance view</span></div>
            <div><strong>4</strong><span>Database platforms</span></div>
            <div><strong>4</strong><span>Priority control domains</span></div>
          </div>
        </div>

        <div className="hero-visual reveal reveal-four" aria-label="Security assurance scope visualization">
          <div className="visual-grid" aria-hidden="true" />
          <div className="orbit orbit-one" aria-hidden="true" />
          <div className="orbit orbit-two" aria-hidden="true" />
          <div className="scope-stage">
            <div className="scope-card glass-card">
              <div className="scope-card-header">
                <div><span className="card-kicker">Assurance scope</span><h2>Control coverage</h2></div>
                <span className="live-status"><span aria-hidden="true" />In focus</span>
              </div>
              <div className="scope-list">
                {SCOPE_ITEMS.map((item) => {
                  const Icon = item.icon;
                  return (
                    <div className="scope-row" key={item.label}>
                      <span className="scope-icon" aria-hidden="true"><Icon size={17} /></span>
                      <span>{item.label}</span>
                      <span className="sr-only">In scope</span>
                      <CircleCheck className="scope-check" size={18} aria-hidden="true" />
                    </div>
                  );
                })}
              </div>
              <div className="platform-strip" aria-label="Supported database platforms">
                {PLATFORM_NAMES.map((platform) => (
                  <span key={platform}><Database size={13} aria-hidden="true" />{platform}</span>
                ))}
              </div>
            </div>
            <div className="signal-card glass-card" aria-hidden="true">
              <div className="signal-icon"><Network size={18} /></div>
              <div><span>Control plane</span><strong>Unified evidence</strong></div>
              <Sparkles size={16} />
            </div>
          </div>
        </div>
      </section>

      <section className="context-strip" aria-label="Program context">
        <div className="context-label"><ScanSearch size={18} aria-hidden="true" />Why now</div>
        <p>
          Modernization can pause. Exposure does not. Strengthen database controls
          now—without waiting for a broader data-platform migration.
        </p>
        <a href="#approach">See the assurance path <ArrowRight size={16} aria-hidden="true" /></a>
      </section>

      <section className="section capabilities-section" id="capabilities" aria-labelledby="capabilities-title">
        <div className="section-heading split-heading">
          <div>
            <span className="section-kicker">Priority control domains</span>
            <h2 id="capabilities-title">Protection where risk becomes real.</h2>
          </div>
          <p>
            Start with the four controls the customer identified, then connect them
            through shared discovery, policy, monitoring, and evidence.
          </p>
        </div>
        <div className="capability-grid">
          {CAPABILITIES.map((capability) => {
            const Icon = capability.icon;
            return (
              <article className="capability-card" key={capability.title}>
                <div className="capability-topline">
                  <span className="capability-icon"><Icon size={21} aria-hidden="true" /></span>
                  <span className="card-number">{capability.number}</span>
                </div>
                <h3>{capability.title}</h3>
                <p>{capability.description}</p>
                <div className="tag-list">
                  {capability.tags.map((tag) => <span key={tag}>{tag}</span>)}
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="section platform-section" id="platforms" aria-labelledby="platforms-title">
        <div className="platform-intro">
          <span className="section-kicker">Heterogeneous by design</span>
          <h2 id="platforms-title">One assurance model. Four database realities.</h2>
          <p>
            Normalize outcomes and evidence while respecting the native security
            capabilities, operating models, and constraints of each platform.
          </p>
        </div>
        <div className="platform-panel">
          <div className="platform-panel-head">
            <span>Platform</span><span>Native control focus</span><span>Status</span>
          </div>
          {PLATFORMS.map((platform) => (
            <article className="platform-row" key={platform.code}>
              <div className="platform-name"><span>{platform.code}</span><h3>{platform.title}</h3></div>
              <p>{platform.description}</p>
              <div className="coverage-status"><Check size={14} aria-hidden="true" />In scope</div>
            </article>
          ))}
        </div>
      </section>

      <section className="section approach-section" id="approach" aria-labelledby="approach-title">
        <div className="section-heading approach-heading">
          <span className="section-kicker">The assurance path</span>
          <h2 id="approach-title">Move from intent to defensible evidence.</h2>
        </div>
        <div className="steps-grid">
          {STEPS.map(([title, description], index) => (
            <article className="step-card" key={title}>
              <div className="step-index">0{index + 1}</div>
              <div className="step-connector" aria-hidden="true"><span /></div>
              <h3>{title}</h3><p>{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section outcomes-section" aria-labelledby="outcomes-title">
        <div className="outcomes-copy">
          <span className="section-kicker">Program outcomes</span>
          <h2 id="outcomes-title">A security priority teams can act on now.</h2>
          <p>
            Build a roadmap that reduces exposure today and remains useful through
            whatever migration or modernization decision comes next.
          </p>
        </div>
        <div className="outcomes-list">
          {["Reduced sensitive-data exposure", "Controlled privileged access", "Safer non-production data", "Audit-ready control evidence"].map((outcome) => (
            <div key={outcome}><CircleCheck size={19} aria-hidden="true" />{outcome}</div>
          ))}
        </div>
      </section>

      <section className="assessment-section" id="assessment" aria-labelledby="assessment-title">
        <div className="assessment-glow" aria-hidden="true" />
        <div className="assessment-icon" aria-hidden="true"><Layers3 size={26} /></div>
        <span className="section-kicker">Your 2026 database security focus</span>
        <h2 id="assessment-title">Turn priorities into an actionable control roadmap.</h2>
        <p>
          Begin with a focused working session to confirm scope, critical databases,
          sensitive-data flows, and the evidence your stakeholders need.
        </p>
        <div className="assessment-actions">
          <Link className="button button-primary" href="/console/assessments">
            Open local assessment <ArrowRight size={17} aria-hidden="true" />
          </Link>
          <span>No platform migration required to begin.</span>
        </div>
      </section>

      <footer className="site-footer">
        <a className="brand footer-brand" href="#top" aria-label="AegisDB home">
          <span className="brand-mark" aria-hidden="true"><Database size={17} /></span><span>AegisDB</span>
        </a>
        <p>Database security assurance for complex estates.</p>
        <span>Oracle · PostgreSQL · Sybase · MySQL</span>
      </footer>
    </main>
  );
}
