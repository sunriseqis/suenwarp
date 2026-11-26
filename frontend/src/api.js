const TOKEN_KEY = 'warpsub_token'

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_KEY)
  }
}

export async function apiFetch(path, options = {}, token = getStoredToken()) {
  const headers = {
    ...(options.headers || {}),
    'X-Warp-Token': token,
  }
  if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(path, { ...options, headers })
  if (res.status === 403) {
    throw new AuthError('访问令牌无效或已过期')
  }
  const text = await res.text()
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(text || `HTTP ${res.status}`)
  }
}

export class AuthError extends Error {}

export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.left = '-9999px'
  ta.style.top = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(ta)
  if (!ok) {
    throw new Error('复制失败，请手动复制')
  }
}
