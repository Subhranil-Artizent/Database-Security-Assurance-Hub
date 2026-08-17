import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, ConsoleActionError, exactForm, failClosedActionResponse, formEnum, formText, operationKey, requireConsoleMutation } from "../../action-utils";

const FIELDS = ["operation_id", "policy_id", "action", "note", "reference"] as const;
const RESOURCE_ID = /^[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    const action = formEnum(form, "action", ["approve", "record_execution", "validate", "archive"] as const);
    const reference = formText(form, "reference", { min: 0, max: 240 }) || undefined;
    if (action === "record_execution" && !reference) throw new ConsoleActionError("invalid_input", 422);
    await getConsoleRepository().transitionMaskingPolicy({
      policyId: formText(form, "policy_id", { min: 36, max: 36, pattern: RESOURCE_ID }),
      action,
      note: formText(form, "note", { min: 3, max: 1_000 }),
      reference,
    }, operationKey(form));
    const notice = action === "approve"
      ? "masking_policy_approved"
      : action === "record_execution"
        ? "masking_execution_recorded"
        : action === "validate"
          ? "masking_policy_validated"
          : "masking_policy_archived";
    return redirectTo(request, `/console/masking?notice=${notice}`);
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/masking?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
