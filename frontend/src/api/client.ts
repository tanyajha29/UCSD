/**
 * Centralized API client for UCSD Backend REST endpoints.
 */

import {
  AnalysisReport,
  AnalysisSummary,
  ComparisonRecord,
  DashboardStats,
  KnowledgeBaseEntry,
  PaginatedAnalyses,
  SystemHealth,
} from '../types';

const API_BASE = '/api';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail || `API Error (${status})`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    let detail = `HTTP Error ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        detail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // Non-JSON response
    }
    throw new ApiError(response.status, detail);
  }

  // Handle empty bodies (e.g. 204 No Content)
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: (): Promise<SystemHealth> => request<SystemHealth>('/health'),

  // Dashboard
  getDashboardStats: (): Promise<DashboardStats> => request<DashboardStats>('/dashboard'),

  // Analyses
  uploadAPK: async (file: File): Promise<{ id: string; status: string; file_name: string }> => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/analyses`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      let detail = `Upload failed: ${response.statusText}`;
      try {
        const errJson = await response.json();
        if (errJson.detail) detail = errJson.detail;
      } catch {}
      throw new ApiError(response.status, detail);
    }

    return response.json();
  },

  listAnalyses: (
    page = 1,
    pageSize = 20,
    status?: string,
    query?: string
  ): Promise<PaginatedAnalyses> => {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    });
    if (status) params.set('status', status);
    if (query) params.set('query', query);

    return request<PaginatedAnalyses>(`/analyses?${params.toString()}`);
  },

  getAnalysisStatus: (id: string): Promise<AnalysisSummary> =>
    request<AnalysisSummary>(`/analyses/${id}`),

  getAnalysisResults: (
    id: string
  ): Promise<{ id: string; status: string; file_name?: string; sha256?: string; report: AnalysisReport }> =>
    request<{ id: string; status: string; file_name?: string; sha256?: string; report: AnalysisReport }>(
      `/analyses/${id}/results`
    ),

  deleteAnalysis: (id: string): Promise<{ message: string; id: string }> =>
    request<{ message: string; id: string }>(`/analyses/${id}`, { method: 'DELETE' }),

  getJsonReportUrl: (id: string): string => `${API_BASE}/analyses/${id}/reports/json`,
  getHtmlReportUrl: (id: string, download = false): string =>
    `${API_BASE}/analyses/${id}/reports/html${download ? '?download=true' : ''}`,
  getAnalysisJsonReportUrl: (id: string): string => `${API_BASE}/analyses/${id}/reports/json`,
  getAnalysisHtmlReportUrl: (id: string, download = false): string =>
    `${API_BASE}/analyses/${id}/reports/html${download ? '?download=true' : ''}`,

  // Cross-APK Comparisons
  createComparison: (analysisIds: string[], title?: string): Promise<ComparisonRecord> =>
    request<ComparisonRecord>('/comparisons', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_ids: analysisIds, title }),
    }),

  listComparisons: (limit = 20): Promise<ComparisonRecord[]> =>
    request<ComparisonRecord[]>(`/comparisons?limit=${limit}`),

  getComparisonDetail: (id: string): Promise<ComparisonRecord> =>
    request<ComparisonRecord>(`/comparisons/${id}`),

  // Knowledge Base
  getKnowledgeBase: (): Promise<{ metadata: any; entries: KnowledgeBaseEntry[] }> =>
    request<{ metadata: any; entries: KnowledgeBaseEntry[] }>('/knowledge-base'),
};
