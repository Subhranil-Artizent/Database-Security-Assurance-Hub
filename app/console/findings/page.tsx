import { FindingsView, type FindingFilters } from "@/components/console/findings-view";

export default async function FindingsPage({ searchParams }: { searchParams: Promise<FindingFilters> }) {
  return <FindingsView filters={await searchParams} />;
}

