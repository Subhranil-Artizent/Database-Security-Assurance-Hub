import "server-only";

import { getChatGPTUser } from "@/app/chatgpt-auth";
import { ConsoleRepositoryError } from "@/components/console/repository";

const MAX_FORM_BYTES = 16 * 1024;

export async function requireConsoleMutation(request: Request): Promise<URLSearchParams> {
  const user = await getChatGPTUser();
  if (!user) throw new ConsoleActionError("unauthenticated", 401);

  const origin = request.headers.get("origin");
  let expectedOrigin: string;
  try { expectedOrigin = new URL(request.url).origin; } catch { throw new ConsoleActionError("csrf", 403); }
  if (!origin || origin !== expectedOrigin) throw new ConsoleActionError("csrf", 403);
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin") throw new ConsoleActionError("csrf", 403);

  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") throw new ConsoleActionError("invalid_input", 415);
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declaredLength) || declaredLength < 1 || declaredLength > MAX_FORM_BYTES) {
    throw new ConsoleActionError("invalid_input", 413);
  }
  const body = await request.text();
  if (!body || body.length > MAX_FORM_BYTES) throw new ConsoleActionError("invalid_input", 413);
  return new URLSearchParams(body);
}

export function exactForm(params: URLSearchParams, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of params.keys()) if (!allowedSet.has(key) || params.getAll(key).length !== 1) throw new ConsoleActionError("invalid_input", 422);
  for (const key of allowed) if (params.getAll(key).length !== 1) throw new ConsoleActionError("invalid_input", 422);
}

export function formText(params: URLSearchParams, name: string, options: { min?: number; max: number; pattern?: RegExp }): string {
  const value = (params.get(name) ?? "").trim();
  if (value.length < (options.min ?? 1) || value.length > options.max || /[\r\n\0]/.test(value) || (options.pattern && !options.pattern.test(value))) {
    throw new ConsoleActionError("invalid_input", 422);
  }
  return value;
}

export function formEnum<T extends string>(params: URLSearchParams, name: string, allowed: readonly T[]): T {
  const value = formText(params, name, { max: 80 });
  if (!allowed.includes(value as T)) throw new ConsoleActionError("invalid_input", 422);
  return value as T;
}

export function operationKey(params: URLSearchParams): string {
  return formText(params, "operation_id", { min: 8, max: 100, pattern: /^[A-Za-z0-9._:-]+$/ });
}

export function actionErrorCode(error: unknown): string {
  if (error instanceof ConsoleActionError) return error.code;
  if (error instanceof ConsoleRepositoryError) {
    if (error.code === "authentication") return "session_expired";
    if (error.code === "authorization") return "forbidden";
    if (error.code === "validation") return "invalid_input";
    if (error.code === "unsupported" || error.code === "configuration") return "demo_read_only";
    if (error.code === "conflict") return "conflict";
    if (error.code === "unavailable") return "service_unavailable";
    if (error.code === "invalid_response") return "invalid_response";
  }
  return "operation_failed";
}

export function failClosedActionResponse(error: unknown): Response | null {
  if (!(error instanceof ConsoleActionError) || ![401, 403, 413, 415].includes(error.status)) return null;
  return Response.json(
    { error: { code: error.code, message: "The console request was rejected." } },
    { status: error.status, headers: { "cache-control": "no-store" } },
  );
}

export class ConsoleActionError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(code);
    this.name = "ConsoleActionError";
  }
}
