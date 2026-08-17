import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, exactForm, failClosedActionResponse, formEnum, formText, operationKey, requireConsoleMutation } from "../action-utils";

const FIELDS = ["operation_id", "name", "classification", "strategy", "target_environment"] as const;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    await getConsoleRepository().createMaskingPolicy({
      name: formText(form, "name", { max: 160 }),
      classification: formText(form, "classification", { max: 100 }),
      strategy: formEnum(form, "strategy", ["redact", "tokenize", "hash", "substitute", "shuffle", "format_preserving"] as const),
      targetEnvironment: formEnum(form, "target_environment", ["development", "test", "staging"] as const),
    }, operationKey(form));
    return redirectTo(request, "/console/masking?notice=masking_policy_created");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/masking?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
