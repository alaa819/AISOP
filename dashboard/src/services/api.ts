const API_BASE_URL = "http://127.0.0.1:8000/api/v1";
const REQUEST_TIMEOUT_MS = 10_000;

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export type ApiErrorCode =
  | "BAD_REQUEST" | "VALIDATION_ERROR" | "INVALID_CREDENTIALS"
  | "UNAUTHORIZED" | "NOT_AUTHENTICATED" | "FORBIDDEN" | "NOT_FOUND"
  | "RATE_LIMITED" | "SERVER_ERROR" | "SERVICE_UNAVAILABLE"
  | "HTTP_ERROR" | "NETWORK_ERROR" | "TIMEOUT" | "CANCELLED"
  | "INVALID_RESPONSE" | "REQUEST_FAILED";

const ERROR_MESSAGES: Record<ApiErrorCode, string> = {
  BAD_REQUEST: "Please check your input and try again.",
  VALIDATION_ERROR: "Please check the required fields and try again.",
  INVALID_CREDENTIALS: "Invalid username or password.",
  UNAUTHORIZED: "Your session has expired. Please sign in again.",
  NOT_AUTHENTICATED: "Please sign in to continue.",
  FORBIDDEN: "You do not have permission to perform this action.",
  NOT_FOUND: "The requested resource was not found.",
  RATE_LIMITED: "Too many requests. Please wait and try again.",
  SERVER_ERROR: "AISOP server encountered an error. Please try again.",
  SERVICE_UNAVAILABLE: "AISOP server is temporarily unavailable. Please try again.",
  HTTP_ERROR: "Unable to complete your request. Please try again.",
  NETWORK_ERROR: "Unable to connect to AISOP server.",
  TIMEOUT: "AISOP server took too long to respond. Please retry.",
  CANCELLED: "Request cancelled.",
  INVALID_RESPONSE: "AISOP server returned an unexpected response. Please try again.",
  REQUEST_FAILED: "Unable to complete your request. Please try again.",
};

/** Messages are chosen locally; backend details and tokens are never attached. */
export class ApiRequestError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number | undefined;
  constructor(code: ApiErrorCode, status?: number) {
    super(ERROR_MESSAGES[code]);
    this.name = "ApiRequestError";
    this.code = code;
    this.status = status;
  }
}

/** Retained for the 5G-1 connection screen; both failures are typed API errors. */
export class ApiNetworkError extends ApiRequestError {
  constructor(code: "NETWORK_ERROR" | "TIMEOUT" = "NETWORK_ERROR", status?: number) {
    super(code, status);
    this.name = "ApiNetworkError";
  }
}

export function getApiErrorMessage(error: unknown): string {
  return error instanceof ApiRequestError ? ERROR_MESSAGES[error.code] : ERROR_MESSAGES.REQUEST_FAILED;
}

export function isBackendUnavailable(error: unknown): boolean {
  return error instanceof ApiRequestError &&
    (error.code === "NETWORK_ERROR" || error.code === "TIMEOUT" || error.code === "SERVICE_UNAVAILABLE");
}

const unauthorizedListeners = new Set<(error: ApiRequestError) => void>();
export function subscribeUnauthorized(listener: (error: ApiRequestError) => void): () => void {
  unauthorizedListeners.add(listener);
  return () => { unauthorizedListeners.delete(listener); };
}

function invalidateSession(token: string | null, error: ApiRequestError): void {
  // Ignore a response from an old session; concurrent 401s notify only once.
  if (getAccessToken() !== token) return;
  logout();
  unauthorizedListeners.forEach(listener => listener(error));
}

function parseHttpError(status: number, path: string, payload?: unknown): ApiRequestError {
  let code: ApiErrorCode;
  switch (status) {
    case 400: code = "BAD_REQUEST"; break;
    case 422: code = "VALIDATION_ERROR"; break;
    case 401: code = path === "/auth/login" ? "INVALID_CREDENTIALS" : "UNAUTHORIZED"; break;
    case 403: code = "FORBIDDEN"; break;
    case 404: code = "NOT_FOUND"; break;
    case 429: code = "RATE_LIMITED"; break;
    case 503: code = "SERVICE_UNAVAILABLE"; break;
    default: code = status >= 500 ? "SERVER_ERROR" : "HTTP_ERROR";
  }
  // Only an exact, familiar login response can affect validation feedback.
  if (path === "/auth/login" && (status === 400 || status === 422) &&
      typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    const safeCredentials = ["invalid credentials", "invalid credentials.",
      "invalid username or password", "invalid username or password.",
      "incorrect username or password", "incorrect username or password."];
    if (typeof detail === "string" && safeCredentials.includes(detail.toLowerCase())) code = "INVALID_CREDENTIALS";
  }
  return new ApiRequestError(code, status);
}

interface ApiRequestOptions {
  method?: "GET" | "POST";
  body?: string;
  authenticated?: boolean;
  signal?: AbortSignal | undefined;
}

/** One transport for all endpoints, including response-body timeout and cancellation. */
export async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const { method = "GET", body, authenticated = true, signal } = options;
  const token = getAccessToken();
  if (authenticated && !token) throw new ApiRequestError("NOT_AUTHENTICATED");
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal?.aborted) controller.abort();
  else signal?.addEventListener("abort", cancel, { once: true });
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let rejectCancellation: (() => void) | undefined;
  let responseStatus: number | undefined;
  try {
    const cancellation = new Promise<never>((_, reject) => {
      rejectCancellation = () => reject(new ApiRequestError("CANCELLED", responseStatus));
      if (controller.signal.aborted) rejectCancellation();
      else controller.signal.addEventListener("abort", rejectCancellation, { once: true });
    });
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        reject(new ApiNetworkError("TIMEOUT", responseStatus));
        controller.abort();
      }, REQUEST_TIMEOUT_MS);
    });
    const request = async (): Promise<T> => {
      if (controller.signal.aborted) throw new ApiRequestError("CANCELLED");
      const response = await fetch(`${API_BASE_URL}${path}`, {
        method, ...(body === undefined ? {} : { body }), signal: controller.signal,
        headers: { "Content-Type": "application/json", ...(authenticated ? { Authorization: `Bearer ${token}` } : {}) },
      });
      responseStatus = response.status;
      if (controller.signal.aborted) throw new ApiRequestError("CANCELLED", responseStatus);
      if (response.status === 401) {
        // Invalidate immediately, even if an error response's body stalls.
        const error = parseHttpError(401, path);
        invalidateSession(token, error);
        throw error;
      }
      if (!response.ok) {
        // Arbitrary error bodies are ignored. Only safe login validation needs parsing.
        const payload: unknown = path === "/auth/login" && (response.status === 400 || response.status === 422)
          ? await response.json().catch(() => undefined) : undefined;
        throw parseHttpError(response.status, path, payload);
      }
      if (response.status === 204) return undefined as T;
      return await response.json() as T;
    };
    return await Promise.race([request(), deadline, cancellation]);
  } catch (error) {
    if (signal?.aborted) throw new ApiRequestError("CANCELLED", responseStatus);
    if (error instanceof ApiRequestError) throw error;
    if (error instanceof SyntaxError) throw new ApiRequestError("INVALID_RESPONSE", responseStatus);
    if (error instanceof TypeError) throw new ApiNetworkError("NETWORK_ERROR", responseStatus);
    throw new ApiRequestError("REQUEST_FAILED", responseStatus);
  } finally {
    clearTimeout(timeout);
    if (rejectCancellation) controller.signal.removeEventListener("abort", rejectCancellation);
    signal?.removeEventListener("abort", cancel);
  }
}

export interface CurrentUser {
  username: string;
  role: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  timestamp: string;
}

export interface StatisticsResponse {
  [key: string]: unknown;
}

export interface Alert {
  id: number | string;
  severity: string;
  title?: string;
  description?: string;
  rule?: string;
  risk_score?: number;
  source?: string;
  timestamp?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface AlertsResponse {
  count: number;
  limit: number;
  offset: number;
  alerts: Alert[];
}

/**
 * Parameters supported by GET /api/v1/alerts.
 */
export interface GetAlertsParams {
  severity?: string | undefined;
  limit?: number;
  offset?: number;
}

/** Explicit logout and actual HTTP 401 are the only API paths that remove the JWT. */
export function logout(): void {
  localStorage.removeItem("aisop_access_token");
}

export function getAccessToken(): string | null {
  return localStorage.getItem("aisop_access_token");
}

export function hasAccessToken(): boolean {
  return getAccessToken() !== null;
}

export async function login(username: string, password: string, signal?: AbortSignal): Promise<LoginResponse> {
  const data = await apiRequest<LoginResponse>("/auth/login", {
    method: "POST", authenticated: false, body: JSON.stringify({ username, password }), signal,
  });
  localStorage.setItem("aisop_access_token", data.access_token);
  return data;
}

export function getCurrentUser(signal?: AbortSignal): Promise<CurrentUser> {
  return apiRequest<CurrentUser>("/auth/me", { signal });
}

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiRequest<HealthResponse>("/health", { authenticated: false, signal });
}

export function getStatistics(signal?: AbortSignal): Promise<StatisticsResponse> {
  return apiRequest<StatisticsResponse>("/statistics", { signal });
}

export function getAlerts(params: GetAlertsParams = {}, signal?: AbortSignal): Promise<AlertsResponse> {
  const query = new URLSearchParams();
  if (params.severity) query.set("severity", params.severity);
  query.set("limit", String(params.limit ?? 10));
  query.set("offset", String(params.offset ?? 0));
  return apiRequest<AlertsResponse>(`/alerts?${query.toString()}`, { signal });
}
