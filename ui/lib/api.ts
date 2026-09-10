const inferredApi =
  typeof window === 'undefined'
    ? 'http://localhost:8765'
    : `${window.location.protocol}//${window.location.hostname}:8765`;

export const API = process.env.NEXT_PUBLIC_AGENT_API_URL ?? inferredApi;

export function csrfToken() {
  return typeof window === 'undefined'
    ? ''
    : (sessionStorage.getItem('sentinel-csrf') ?? '');
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (init.method && !['GET', 'HEAD'].includes(init.method.toUpperCase())) {
    headers.set('x-csrf-token', csrfToken());
  }
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers,
    credentials: 'include',
  });
  let detail = '';
  if (response.status === 401 || response.status === 403) {
    try {
      detail =
        ((await response.clone().json()) as { detail?: string }).detail ?? '';
    } catch {
      // The caller still receives the original response and handles malformed errors.
    }
  }
  if (
    response.status === 401 &&
    detail === 'Authentication required' &&
    typeof window !== 'undefined' &&
    !location.pathname.startsWith('/login')
  )
    location.replace('/login');
  if (
    response.status === 403 &&
    detail === 'Password change required' &&
    typeof window !== 'undefined' &&
    !location.pathname.startsWith('/change-password')
  )
    location.replace('/change-password');
  return response;
}
