import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

export const apiClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30_000,
})

// In-flight login promise deduplicator
let activeLoginPromise: Promise<string | null> | null = null

async function getOrCreateSessionToken(): Promise<string | null> {
  if (typeof window === 'undefined') return null

  const existingToken = localStorage.getItem('token')
  if (existingToken) return existingToken

  if (activeLoginPromise) return activeLoginPromise

  activeLoginPromise = (async () => {
    try {
      // Authenticate with standard demo admin credentials
      const res = await axios.post<{ access_token: string }>(`${baseURL}/api/v1/auth/login`, {
        email: 'admin@zentry.com',
        password: 'ZentrySecurity2026!',
      })
      if (res.data?.access_token) {
        localStorage.setItem('token', res.data.access_token)
        return res.data.access_token
      }
    } catch {
      // Fallback silently if offline
    } finally {
      activeLoginPromise = null
    }
    return null
  })()

  return activeLoginPromise
}

// Request Interceptor: Attach token, automatically establishing a verified session if missing
apiClient.interceptors.request.use(async (config) => {
  const token = await getOrCreateSessionToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response Interceptor: If a 401 is received, re-authenticate once and retry
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      localStorage.removeItem('token')
      const newToken = await getOrCreateSessionToken()
      if (newToken) {
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return apiClient(originalRequest)
      }
    }
    return Promise.reject(error)
  },
)

export default apiClient
