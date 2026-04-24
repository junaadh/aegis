import type { IncomingHttpHeaders, IncomingMessage } from "node:http";

export type AegisRequestLike =
  | Request
  | { headers: HeadersInit }
  | IncomingMessage;

function readObjectHeader(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

function readHeadersInitHeader(
  headers: HeadersInit,
  name: string,
): string | undefined {
  if (headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }

  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      if (key.toLowerCase() === name.toLowerCase()) {
        return value;
      }
    }

    return undefined;
  }

  return readObjectHeader(headers, name);
}

export function getHeader(
  request: AegisRequestLike,
  name: string,
): string | undefined {
  if (request instanceof Request) {
    return request.headers.get(name) ?? undefined;
  }

  const { headers } = request;

  if (headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }

  if (Array.isArray(headers)) {
    return readHeadersInitHeader(headers, name);
  }

  return readObjectHeader(headers, name);
}

export function getCookieHeader(request: AegisRequestLike): string | undefined {
  return getHeader(request, "cookie");
}

export function getBearerToken(
  request: AegisRequestLike,
): string | undefined {
  const header = getHeader(request, "authorization");
  if (!header) {
    return undefined;
  }

  const match = header.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
}

export function getCookieValue(
  cookieHeader: string | undefined,
  name: string,
): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }

  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === name) {
      return rawValue.join("=");
    }
  }

  return undefined;
}
