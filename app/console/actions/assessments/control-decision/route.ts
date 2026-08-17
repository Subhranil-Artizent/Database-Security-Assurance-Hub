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

const FIELDS = [
  "operation_id",
  "assessment_id",
  "control_definition_id",
  "outcome",
  "rationale",
] as const;
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
    await getConsoleRepository().saveControlDecision({
      assessmentId,
      controlDefinitionId: formText(form, "control_definition_id", {
        min: 36,
        max: 36,
        pattern: RESOURCE_ID,
      }),
      outcome: formEnum(form, "outcome", ["passed", "failed", "not_applicable"] as const),
      rationale: formText(form, "rationale", { min: 10, max: 2_000 }),
    }, operationKey(form));
    return redirectTo(request, `${assessmentPath}?notice=control_decision_saved`);
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `${assessmentPath}?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
