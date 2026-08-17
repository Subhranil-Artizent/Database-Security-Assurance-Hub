import { AssessmentsView, type AssessmentFilters } from "@/components/console/assessments-view";

export default async function AssessmentsPage({ searchParams }: { searchParams: Promise<AssessmentFilters> }) {
  return <AssessmentsView filters={await searchParams} />;
}

