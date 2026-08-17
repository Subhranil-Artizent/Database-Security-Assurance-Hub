/** Cloudflare Worker entry point for the Database Security Assurance Hub. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface AssetFetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

interface Env {
  ASSETS: AssetFetcher;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
].join("; ");

function requestIdFor(request: Request): string {
  const candidate = request.headers.get("x-request-id");
  return candidate && REQUEST_ID_PATTERN.test(candidate)
    ? candidate
    : crypto.randomUUID();
}

function secureResponse(
  response: Response,
  request: Request,
  requestId: string,
): Response {
  const secured = new Response(response.body, response);
  secured.headers.set("x-request-id", requestId);
  secured.headers.set("x-content-type-options", "nosniff");
  secured.headers.set("x-frame-options", "DENY");
  secured.headers.set("referrer-policy", "strict-origin-when-cross-origin");
  secured.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  secured.headers.set("cross-origin-opener-policy", "same-origin");
  secured.headers.set("cross-origin-resource-policy", "same-site");
  secured.headers.set("content-security-policy", CONTENT_SECURITY_POLICY);
  if (new URL(request.url).protocol === "https:") {
    secured.headers.set(
      "strict-transport-security",
      "max-age=31536000; includeSubDomains",
    );
  }
  return secured;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const requestId = requestIdFor(request);

    if (url.pathname === "/healthz" || url.pathname === "/readyz") {
      return secureResponse(
        Response.json(
          {
            status: "ok",
            service: "aegisdb-web",
            timestamp: new Date().toISOString(),
          },
          { headers: { "cache-control": "no-store" } },
        ),
        request,
        requestId,
      );
    }

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const response = await handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return secureResponse(response, request, requestId);
    }

    const response = await handler.fetch(request, env, ctx);
    return secureResponse(response, request, requestId);
  },
};

export default worker;
