const API_BASE_URL = "http://127.0.0.1:8000/api/v1";

interface LoginResponse {
  access_token: string;
  token_type: string;
}

interface ApiError {
  detail?: string;
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
 * Login to AISOP API and store the JWT token.
 */
export async function login(
  username: string,
  password: string
): Promise<LoginResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      password,
    }),
  });

  if (!response.ok) {
    const error: ApiError = await response.json().catch(() => ({}));

    throw new Error(error.detail || "Login failed");
  }

  const data: LoginResponse = await response.json();

  localStorage.setItem("aisop_access_token", data.access_token);

  return data;
}

/**
 * Remove the stored JWT token.
 */
export function logout(): void {
  localStorage.removeItem("aisop_access_token");
}

/**
 * Get the stored JWT token.
 */
export function getAccessToken(): string | null {
  return localStorage.getItem("aisop_access_token");
}

/**
 * Build authenticated request headers.
 */
function getAuthHeaders(): HeadersInit {
  const token = getAccessToken();

  if (!token) {
    throw new Error("Not authenticated");
  }

  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

/**
 * Check whether the AISOP API is healthy.
 */
export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error("AISOP API is unavailable");
  }

  return response.json();
}

/**
 * Get dashboard statistics.
 */
export async function getStatistics(): Promise<StatisticsResponse> {
  const response = await fetch(`${API_BASE_URL}/statistics`, {
    method: "GET",
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    const error: ApiError = await response.json().catch(() => ({}));

    throw new Error(error.detail || "Failed to load statistics");
  }

  return response.json();
}

/**
 * Get alerts from AISOP.
 */
export async function getAlerts(): Promise<AlertsResponse> {
  const response = await fetch(`${API_BASE_URL}/alerts`, {
    method: "GET",
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    const error: ApiError = await response.json().catch(() => ({}));

    throw new Error(error.detail || "Failed to load alerts");
  }

  return response.json();
}
