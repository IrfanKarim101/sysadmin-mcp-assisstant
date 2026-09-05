export const API = process.env.NEXT_PUBLIC_AGENT_API_URL ?? 'http://localhost:8765';

export function csrfToken() {
  return typeof window === 'undefined' ? '' : sessionStorage.getItem('sentinel-csrf') ?? '';
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (init.method && !['GET', 'HEAD'].includes(init.method.toUpperCase())) {
    headers.set('x-csrf-token', csrfToken());
  }
  const response = await fetch(`${API}${path}`, { ...init, headers, credentials: 'include' });
  if (response.status === 401 && typeof window !== 'undefined' && !location.pathname.startsWith('/login')) location.assign('/login');
  if (response.status === 403 && typeof window !== 'undefined' && !location.pathname.startsWith('/change-password')) location.assign('/change-password');
  return response;
}
