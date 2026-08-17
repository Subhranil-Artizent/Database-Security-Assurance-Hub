import { AssetsView, type AssetFilters } from "@/components/console/assets-view";

export default async function AssetsPage({ searchParams }: { searchParams: Promise<AssetFilters> }) {
  return <AssetsView filters={await searchParams} />;
}

