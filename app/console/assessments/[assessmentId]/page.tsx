import {
  AssessmentReviewView,
  type AssessmentReviewFilters,
} from "@/components/console/assessment-review-view";

export default async function AssessmentReviewPage({
  params,
  searchParams,
}: {
  params: Promise<{ assessmentId: string }>;
  searchParams: Promise<AssessmentReviewFilters>;
}) {
  const [{ assessmentId }, filters] = await Promise.all([params, searchParams]);
  return <AssessmentReviewView assessmentId={assessmentId} filters={filters} />;
}
