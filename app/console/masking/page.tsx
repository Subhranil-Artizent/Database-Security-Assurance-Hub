import { MaskingView } from "@/components/console/masking-view";

export default async function MaskingGovernancePage({ searchParams }: { searchParams: Promise<{ cursor?: string; notice?: string; error?: string }> }) {
  return <MaskingView filters={await searchParams} />;
}
