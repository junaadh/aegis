export type AegisApiMeta = {
  requestId: string;
  timestamp: string;
};

export type AegisApiErrorBody = {
  code: string;
  message: string;
  details?: unknown;
};

export type AegisApiOkResponse<T> = {
  data: T;
  meta: AegisApiMeta;
};

export type AegisApiErrResponse = {
  error: AegisApiErrorBody;
  meta: AegisApiMeta;
};

export type AegisApiResponse<T> = AegisApiOkResponse<T> | AegisApiErrResponse;

export class AegisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AegisError";
  }
}

export class AegisConfigurationError extends AegisError {
  constructor(message: string) {
    super(message);
    this.name = "AegisConfigurationError";
  }
}

export class AegisInvalidResponseError extends AegisError {
  constructor(message: string, public readonly causeValue?: unknown) {
    super(message);
    this.name = "AegisInvalidResponseError";
  }
}

export class AegisApiError extends AegisError {
  constructor(
    public readonly response: AegisApiErrResponse,
    public readonly status: number,
  ) {
    super(response.error.message);
    this.name = "AegisApiError";
  }

  get code(): string {
    return this.response.error.code;
  }

  get details(): unknown {
    return this.response.error.details;
  }

  get meta(): AegisApiMeta {
    return this.response.meta;
  }

  get requestId(): string {
    return this.response.meta.requestId;
  }
}
