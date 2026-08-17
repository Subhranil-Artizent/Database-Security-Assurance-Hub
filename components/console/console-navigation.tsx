"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Blend,
  Cable,
  Database,
  FileCheck2,
  FileText,
  LayoutDashboard,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
  UsersRound,
} from "lucide-react";
import styles from "./console.module.css";

const primaryNavigation = [
  { href: "/console", label: "Overview", icon: LayoutDashboard },
  { href: "/console/assets", label: "Database assets", icon: Database },
  { href: "/console/assessments", label: "Assessments", icon: ShieldCheck },
  { href: "/console/findings", label: "Findings", icon: TriangleAlert },
];

const assuranceNavigation = [
  { href: "/console/data-discovery", label: "Data discovery", icon: ScanSearch },
  { href: "/console/access", label: "Access security", icon: UsersRound },
  { href: "/console/masking", label: "Data masking", icon: Blend },
  { href: "/console/evidence", label: "Evidence library", icon: FileCheck2 },
  { href: "/console/report", label: "Management report", icon: FileText },
];

function CurrentLink({
  href,
  label,
  icon: Icon,
  count,
}: {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  count?: string;
}) {
  const pathname = usePathname();
  const isCurrent = pathname === href;

  return (
    <Link href={href} aria-current={isCurrent ? "page" : undefined}>
      <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
      <span>{label}</span>
      {count ? <small aria-label={`${count} items`}>{count}</small> : null}
    </Link>
  );
}

export function ConsoleNavigation() {
  return (
    <nav className={styles.navigation} aria-label="Console navigation">
      <p className={styles.navLabel}>Command center</p>
      <ul>
        {primaryNavigation.map((item) => (
          <li key={item.href}>
            <CurrentLink {...item} />
          </li>
        ))}
      </ul>

      <p className={styles.navLabel}>Assurance domains</p>
      <ul>
        {assuranceNavigation.map((item) => (
          <li key={item.href}>
            <CurrentLink {...item} />
          </li>
        ))}
      </ul>

      <p className={styles.navLabel}>Administration</p>
      <ul>
        <li>
          <CurrentLink href="/console/admin/connectors" label="Collectors" icon={Cable} />
        </li>
      </ul>
    </nav>
  );
}
