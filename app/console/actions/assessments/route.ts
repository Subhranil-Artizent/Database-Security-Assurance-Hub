import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, exactForm, failClosedActionResponse, formText, operationKey, requireConsoleMutation } from "../action-utils";

const FIELDS = ["operation_id", "assessment_target"] as const;
const ASSESSMENT_TARGET = /^[a-f0-9-]{36}:[a-f0-9-]{36}:[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    await getConsoleRepository().startAssessmentTarget(
      formText(form, "assessment_target", {
        min: 110,
        max: 110,
        pattern: ASSESSMENT_TARGET,
      }),
      operationKey(form),
    );
    return redirectTo(request, "/console/assessments?notice=assessment_queued");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/assessments?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
