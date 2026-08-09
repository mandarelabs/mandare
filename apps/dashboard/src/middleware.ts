import { NextResponse, type NextRequest } from 'next/server';

/**
 * DNS-rebinding defense (S7 review M2), mirroring the gateway's Host
 * allowlist: a browser tricked onto an attacker hostname that rebinds to
 * 127.0.0.1 would otherwise read fleet data and POST the kill action as a
 * same-origin page. Loopback names are always allowed; anything else must
 * be declared in MANDARE_DASHBOARD_ALLOWED_HOSTS (comma-separated). This is
 * a browser defense — real multi-user exposure needs an authenticating
 * reverse proxy in front (see docs: self-hosting).
 */

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

export function hostnameOf(hostHeader: string): string {
  const trimmed = hostHeader.trim().toLowerCase();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end === -1 ? trimmed : trimmed.slice(0, end + 1);
  }
  const colon = trimmed.indexOf(':');
  return colon === -1 ? trimmed : trimmed.slice(0, colon);
}

export function isHostAllowed(hostHeader: string | null, extraHosts: string): boolean {
  if (hostHeader === null || hostHeader === '') {
    return false;
  }
  const hostname = hostnameOf(hostHeader);
  if (LOOPBACK.has(hostname)) {
    return true;
  }
  return extraHosts
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host.length > 0)
    .includes(hostname);
}

export function middleware(request: NextRequest): NextResponse {
  const allowed = isHostAllowed(
    request.headers.get('host'),
    process.env.MANDARE_DASHBOARD_ALLOWED_HOSTS ?? ''
  );
  if (!allowed) {
    return new NextResponse('host not allowed (set MANDARE_DASHBOARD_ALLOWED_HOSTS)', { status: 403 }) as NextResponse;
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
