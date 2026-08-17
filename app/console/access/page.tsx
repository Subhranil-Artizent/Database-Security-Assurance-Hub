import { AccessView } from "@/components/console/access-view";

export default async function AccessSecurityPage({ searchParams }: { searchParams: Promise<{ cursor?: string; notice?: string; error?: string }> }) {
  return <AccessView filters={await searchParams} />;
}
