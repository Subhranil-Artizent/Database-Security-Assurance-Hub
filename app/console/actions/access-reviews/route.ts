import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, exactForm, failClosedActionResponse, formEnum, formText, operationKey, requireConsoleMutation } from "../action-utils";

const FIELDS = ["operation_id", "review_id", "status", "reason"] as const;
const RESOURCE_ID = /^[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    await getConsoleRepository().updateAccessReview({
      reviewId: formText(form, "review_id", { min: 36, max: 36, pattern: RESOURCE_ID }),
      status: formEnum(form, "status", ["approved", "remediation_required", "closed"] as const),
      reason: formText(form, "reason", { min: 3, max: 1_000 }),
    }, operationKey(form));
    return redirectTo(request, "/console/access?notice=access_review_updated");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/access?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
