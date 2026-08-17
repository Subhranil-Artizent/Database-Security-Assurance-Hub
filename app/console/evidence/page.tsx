import { EvidenceView, type EvidenceFilters } from "@/components/console/evidence-view";

export default async function EvidenceLibraryPage({ searchParams }: { searchParams: Promise<EvidenceFilters> }) {
  return <EvidenceView filters={await searchParams} />;
}
