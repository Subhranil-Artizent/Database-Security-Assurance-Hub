import type { Metadata } from "next";
import { requireChatGPTUser } from "@/app/chatgpt-auth";
import { ConsoleShell } from "@/components/console/console-shell";
import { getConsoleDataMode, getLocalMySqlMode, getLocalSyntheticCollectionMode } from "@/components/console/repository";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Security Assurance Console | AegisDB",
  description: "Database security posture, findings, evidence, and remediation across Oracle, PostgreSQL, Sybase ASE, and MySQL.",
};

export default async function ConsoleLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const user = await requireChatGPTUser("/console");
  return (
    <ConsoleShell
      user={user}
      dataMode={getConsoleDataMode()}
      localMySql={getLocalMySqlMode()}
      syntheticCollection={getLocalSyntheticCollectionMode()}
    >
      {children}
    </ConsoleShell>
  );
}
