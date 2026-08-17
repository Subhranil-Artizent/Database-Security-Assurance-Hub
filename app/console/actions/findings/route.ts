import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, exactForm, failClosedActionResponse, formEnum, formText, operationKey, requireConsoleMutation } from "../action-utils";

const FIELDS = ["operation_id", "finding_id", "status", "owner", "due_date", "reason"] as const;
const RESOURCE_ID = /^[a-f0-9-]{36}$/;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    const dueDate = formText(form, "due_date", { min: 0, max: 10, pattern: /^(?:\d{4}-\d{2}-\d{2})?$/ });
    const dueAt = dueDate ? new Date(`${dueDate}T23:59:59+05:30`) : null;
    if (dueAt && Number.isNaN(dueAt.valueOf())) throw new Error("invalid date");
    await getConsoleRepository().updateFinding({
      findingId: formText(form, "finding_id", { min: 36, max: 36, pattern: RESOURCE_ID }),
      status: formEnum(form, "status", ["open", "in_progress", "resolved"] as const),
      owner: formText(form, "owner", { min: 0, max: 160 }) || undefined,
      dueAt: dueAt?.toISOString(),
      reason: formText(form, "reason", { min: 3, max: 2_000 }),
    }, operationKey(form));
    return redirectTo(request, "/console/findings?notice=finding_updated");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/findings?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
