import { DiscoveryView } from "@/components/console/discovery-view";

export default async function DataDiscoveryPage({ searchParams }: { searchParams: Promise<{ cursor?: string }> }) {
  return <DiscoveryView cursor={(await searchParams).cursor} />;
}
