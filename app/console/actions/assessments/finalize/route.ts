import { NextResponse } from "next/server";

import { getConsoleRepository } from "@/components/console/repository";
import {
  actionErrorCode,
  exactForm,
  failClosedActionResponse,
  formEnum,
  formText,
  operationKey,
  requireConsoleMutation,
} from "../../action-utils";

const FIELDS = ["operation_id", "assessment_id", "confirmation"] as const;
const RESOURCE_ID = /^[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  let assessmentPath = "/console/assessments";
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    const assessmentId = formText(form, "assessment_id", {
      min: 36,
      max: 36,
      pattern: RESOURCE_ID,
    });
    assessmentPath = `/console/assessments/${encodeURIComponent(assessmentId)}`;
    formEnum(form, "confirmation", ["finalize"] as const);
    await getConsoleRepository().finalizeAssessment(
      assessmentId,
      operationKey(form),
    );
    return redirectTo(request, `${assessmentPath}?notice=assessment_finalized`);
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `${assessmentPath}?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
