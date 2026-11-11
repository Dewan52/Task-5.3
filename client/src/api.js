import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- CSRF protection --------------------------------------------------------
// The server needs a secret CSRF token in the `x-csrf-token` header on every
// state-changing request. We fetch it from GET /csrf-token (only our own origin
// can read that response) and keep it in memory.
const SAFE_METHODS = ['get', 'head', 'options']
// These change the session, and the CSRF token is tied to the session, so get a new one after them.
const SESSION_ROUTES = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

function fetchCsrfToken() {
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

function isSafe(config) {
  return SAFE_METHODS.includes((config.method || 'get').toLowerCase())
}

api.interceptors.request.use(async config => {
  if (!isSafe(config)) {
    const token = csrfToken || await fetchCsrfToken()
    config.headers.set('x-csrf-token', token)
  }
  return config
})

api.interceptors.response.use(
  res => {
    if (SESSION_ROUTES.some(r => (res.config.url || '').includes(r))) csrfToken = null
    return res
  },
  async err => {
    const config = err.config
    // A stale/missing CSRF token gives a 403: fetch a fresh one and retry once.
    if (err.response?.status === 403 && config && !isSafe(config) && !config._csrfRetried) {
      config._csrfRetried = true
      csrfToken = null
      await fetchCsrfToken()
      config.headers.set('x-csrf-token', csrfToken)
      return api.request(config)
    }
    return Promise.reject(err)
  }
)
