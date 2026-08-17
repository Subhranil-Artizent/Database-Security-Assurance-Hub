import { NextResponse } from "next/server";
import { getConsoleRepository } from "@/components/console/repository";
import { actionErrorCode, exactForm, failClosedActionResponse, formEnum, formText, operationKey, requireConsoleMutation } from "../action-utils";

const FIELDS = ["operation_id", "external_id", "name", "platform", "version", "edition", "environment", "owner", "criticality"] as const;

export async function POST(request: Request) {
  try {
    const form = await requireConsoleMutation(request);
    exactForm(form, FIELDS);
    await getConsoleRepository().createAsset({
      externalId: formText(form, "external_id", { max: 128 }),
      name: formText(form, "name", { max: 160 }),
      platform: formEnum(form, "platform", ["oracle", "postgresql", "sybase", "mysql"] as const),
      version: formText(form, "version", { max: 80 }),
      edition: formText(form, "edition", { min: 0, max: 120 }) || undefined,
      environment: formEnum(form, "environment", ["production", "staging", "test", "development", "disaster_recovery"] as const),
      owner: formText(form, "owner", { max: 160 }),
      criticality: formEnum(form, "criticality", ["critical", "high", "medium", "low"] as const),
    }, operationKey(form));
    return redirectTo(request, "/console/assets?notice=asset_registered");
  } catch (error) {
    const rejection = failClosedActionResponse(error);
    if (rejection) return rejection;
    return redirectTo(request, `/console/assets?error=${actionErrorCode(error)}`);
  }
}

function redirectTo(request: Request, path: string): NextResponse {
  return NextResponse.redirect(new URL(path, request.url), 303);
}
