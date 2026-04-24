import {
  AegisClientConfig,
  AegisLogger,
  normalizeBaseUrl,
} from "./config";
import {
  AegisApiErrResponse,
  AegisApiResponse,
  AegisApiError,
  AegisConfigurationError,
  AegisInvalidResponseError,
} from "./errors";

type QueryValue = string | number | boolean | null | undefined;

export type AegisAuthMode = "none" | "session" | "internal";

export type AegisRequestOptions<TBody = unknown> = {
  auth?: AegisAuthMode;
  body?: TBody;
  query?: Record<string, QueryValue>;
  headers?: HeadersInit;
  signal?: AbortSignal;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function buildQueryString(query?: Record<string, QueryValue>): string {
  if (!query) {
    return "";
  }

  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) {
      continue;
    }

    params.set(key, String(value));
  }

  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

function parseResponseEnvelope<T>(value: unknown): AegisApiResponse<T> {
  if (!isRecord(value)) {
    throw new AegisInvalidResponseError("Aegis response was not an object", value);
  }

  const meta = value.meta;
  if (!isRecord(meta) || typeof meta.requestId !== "string" || typeof meta.timestamp !== "string") {
    throw new AegisInvalidResponseError("Aegis response meta was invalid", value);
  }

  if ("error" in value && value.error !== undefined && value.error !== null) {
    const error = value.error;
    if (!isRecord(error) || typeof error.code !== "string" || typeof error.message !== "string") {
      throw new AegisInvalidResponseError("Aegis error response was invalid", value);
    }

    return value as AegisApiErrResponse;
  }

  if (!("data" in value)) {
    throw new AegisInvalidResponseError("Aegis success response was missing data", value);
  }

  return value as AegisApiResponse<T>;
}

export class AegisHttpClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly defaultHeaders: HeadersInit | undefined;
  private readonly credentials: RequestCredentials;
  private readonly token: string | undefined;
  private readonly internalToken: string | undefined;
  private readonly logger: AegisLogger | undefined;

  constructor(config: AegisClientConfig) {
    this.baseUrl = normalizeBaseUrl(config.baseUrl);
    this.fetchImpl = config.fetch ?? fetch;
    this.defaultHeaders = config.headers;
    this.credentials = config.credentials ?? "include";
    this.token = config.token;
    this.internalToken = config.internalToken;
    this.logger = config.logger;
  }

  async get<TResponse>(
    path: string,
    options?: Omit<AegisRequestOptions, "body">,
  ): Promise<TResponse> {
    return this.request<TResponse>("GET", path, options);
  }

  async post<TResponse, TBody = unknown>(
    path: string,
    options?: AegisRequestOptions<TBody>,
  ): Promise<TResponse> {
    return this.request<TResponse, TBody>("POST", path, options);
  }

  async patch<TResponse, TBody = unknown>(
    path: string,
    options?: AegisRequestOptions<TBody>,
  ): Promise<TResponse> {
    return this.request<TResponse, TBody>("PATCH", path, options);
  }

  async put<TResponse, TBody = unknown>(
    path: string,
    options?: AegisRequestOptions<TBody>,
  ): Promise<TResponse> {
    return this.request<TResponse, TBody>("PUT", path, options);
  }

  async request<TResponse, TBody = unknown>(
    method: string,
    path: string,
    options: AegisRequestOptions<TBody> = {},
  ): Promise<TResponse> {
    const { auth = "none", body, query, headers, signal } = options;
    const token = this.resolveToken(auth);
    const url = `${this.baseUrl}/v1${path}${buildQueryString(query)}`;
    const start = Date.now();
    const requestInit: RequestInit = {
      method,
      headers: this.buildHeaders(headers, token, body !== undefined),
      credentials: this.credentials,
    };

    if (body !== undefined) {
      requestInit.body = JSON.stringify(body);
    }

    if (signal) {
      requestInit.signal = signal;
    }

    this.log("debug", "Aegis request started", {
      method,
      path,
      url,
      auth,
      hasBody: body !== undefined,
    });

    const response = await this.fetchImpl(url, requestInit);

    let json: unknown;
    try {
      json = await response.json();
    } catch {
      this.log("error", "Aegis response was not valid JSON", {
        method,
        path,
        url,
        status: response.status,
        durationMs: Date.now() - start,
      });
      throw new AegisInvalidResponseError("Aegis response was not valid JSON");
    }

    let envelope: AegisApiResponse<TResponse>;
    try {
      envelope = parseResponseEnvelope<TResponse>(json);
    } catch (error) {
      this.log("error", "Aegis response envelope was invalid", {
        method,
        path,
        url,
        status: response.status,
        durationMs: Date.now() - start,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    if (!response.ok || "error" in envelope) {
      const errorResponse = envelope as AegisApiErrResponse;
      this.log("error", "Aegis request failed", {
        method,
        path,
        url,
        status: response.status,
        durationMs: Date.now() - start,
        requestId: errorResponse.meta.requestId,
        code: errorResponse.error.code,
        message: errorResponse.error.message,
      });
      throw new AegisApiError(envelope as AegisApiErrResponse, response.status);
    }

    if (envelope.data === undefined || envelope.data === null) {
      this.log("error", "Aegis success response data was empty", {
        method,
        path,
        url,
        status: response.status,
        durationMs: Date.now() - start,
        requestId: envelope.meta.requestId,
      });
      throw new AegisInvalidResponseError("Aegis success response data was empty", envelope);
    }

    this.log("info", "Aegis request succeeded", {
      method,
      path,
      url,
      status: response.status,
      durationMs: Date.now() - start,
      requestId: envelope.meta.requestId,
    });

    return envelope.data;
  }

  private log(
    level: keyof AegisLogger,
    message: string,
    context: Record<string, unknown>,
  ): void {
    this.logger?.[level]?.(message, context);
  }

  private buildHeaders(
    headers: HeadersInit | undefined,
    token: string | undefined,
    hasBody: boolean,
  ): Headers {
    const merged = new Headers(this.defaultHeaders);
    if (headers) {
      new Headers(headers).forEach((value, key) => {
        merged.set(key, value);
      });
    }

    merged.set("accept", "application/json");
    if (hasBody) {
      merged.set("content-type", "application/json");
    }
    if (token) {
      merged.set("authorization", `Bearer ${token}`);
    }

    return merged;
  }

  private resolveToken(auth: AegisAuthMode): string | undefined {
    if (auth === "none") {
      return undefined;
    }

    if (auth === "session") {
      return this.token;
    }

    if (!this.internalToken) {
      throw new AegisConfigurationError(
        "This request requires an internalToken in AegisClient config",
      );
    }

    return this.internalToken;
  }
}
