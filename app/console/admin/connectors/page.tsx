import { ConnectorsView } from "@/components/console/connectors-view";

export default async function ConnectorsPage({ searchParams }: { searchParams: Promise<{ cursor?: string }> }) {
  return <ConnectorsView cursor={(await searchParams).cursor} />;
}
