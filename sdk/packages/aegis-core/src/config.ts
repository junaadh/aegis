export type AegisFetch = typeof fetch;

export type AegisLogContext = Record<string, unknown>;

export type AegisLogger = {
  debug?: (message: string, context?: AegisLogContext) => void;
  info?: (message: string, context?: AegisLogContext) => void;
  warn?: (message: string, context?: AegisLogContext) => void;
  error?: (message: string, context?: AegisLogContext) => void;
};

export type AegisClientConfig = {
  baseUrl: string;
  token?: string;
  internalToken?: string;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  fetch?: AegisFetch;
  logger?: AegisLogger;
};

export function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}
