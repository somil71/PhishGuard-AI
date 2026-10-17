/**
 * PhishGuard-AI API Service
 * Handles communication with the FastAPI SOC backend.
 */

const getBaseUrl = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  // When running Vite dev server on port 5173, point to backend on port 8000
  if (typeof window !== 'undefined') {
    if (window.location.port === '5173' || window.location.port === '3000') {
      return 'http://localhost:8000';
    }
    return window.location.origin;
  }
  return 'http://localhost:8000';
};

const BASE_URL = getBaseUrl();

async function handleResponse(res) {
  if (!res.ok) {
    let errorDetail = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const data = await res.json();
      if (data && data.detail) {
        errorDetail = data.detail;
      }
    } catch {
      // Keep default error text
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

/**
 * Perform single URL ML inference and SHAP explainability analysis
 * @param {string} url
 * @param {boolean} includeShap
 */
export async function analyzeUrl(url, includeShap = true) {
  const res = await fetch(`${BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      url: url.trim(),
      include_shap: includeShap,
    }),
  });
  return handleResponse(res);
}

/**
 * Analyze multiple URLs in bulk (up to 100)
 * @param {string[]} urls
 */
export async function batchAnalyzeUrls(urls) {
  const cleanUrls = urls.map(u => u.trim()).filter(Boolean);
  const res = await fetch(`${BASE_URL}/api/batch-analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      urls: cleanUrls,
    }),
  });
  return handleResponse(res);
}

/**
 * Fetch curated sample URLs for quick testing
 */
export async function getSampleUrls() {
  const res = await fetch(`${BASE_URL}/api/samples`);
  return handleResponse(res);
}

/**
 * Fetch ML benchmark metrics, ROC curves, confusion matrices, and model comparison data
 */
export async function getModelMetrics() {
  const res = await fetch(`${BASE_URL}/api/metrics`);
  return handleResponse(res);
}

/**
 * Fetch extracted feature definitions, statistics, and metadata
 */
export async function getFeatureMetadata() {
  const res = await fetch(`${BASE_URL}/api/features`);
  return handleResponse(res);
}

/**
 * Check backend operational health and model readiness
 */
export async function getHealthStatus() {
  const res = await fetch(`${BASE_URL}/api/health`);
  return handleResponse(res);
}
