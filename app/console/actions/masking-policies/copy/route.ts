import { NextResponse } from "next/server";

import { getConsoleRepository } from "@/components/console/repository";
import {
  actionErrorCode,
  exactForm,
  failClosedActionResponse,
  formText,
  operationKey,
  requireConsoleMutation,
} from "../../action-utils";

const FIELDS = ["operation_id", "policy_id"] as const;
const RESOURCE_ID = /^[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    await getConsoleRepository().queueMaskingCopy(
      formText(form, "policy_id", { min: 36, max: 36, pattern: RESOURCE_ID }),
      operationKey(form),
    );
    return redirectTo(request, "/console/masking?notice=masking_copy_queued");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/masking?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
