import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { authRoutes } from './routes/auth'
import { oidcRoutes } from './routes/oidc'
import { getAuthPort, getBindHost, getJwtSecret, getAllowedOrigins, nodeEnv } from './config'
import { authReadiness } from './lib/readiness'

export const app = new Hono()

// CORS FIRST, before ALL routes (incl. /health — CORS-harmless).
// Exact-origin echo from the allowlist shared with the OIDC
// redirect-uri check (src/routes/oidc.ts consumes getAllowedOrigins()
// read-only; its semantics are untouched). Never `*` with credentials:
// non-allowlisted origins get NO ACAO echo. Preflight short-circuits
// here with 204, so OPTIONS never requires auth.
// allowHeaders covers Authorization + Content-Type: no auth route reads
// Idempotency-Key (only provision-hook docs mention it), so it is NOT
// allowlisted — no cargo-cult headers.
// Credential-scope guard: Hono's cors() emits Allow-Credentials whenever
// credentials:true, even with no origin match. A grant without an ACAO echo
// is spec-inert, but this service never sends one — strip it so credentials
// are only ever allowed alongside an echoed allowlist origin.
app.use('*', async (c, next) => {
  await next()
  if (!c.res.headers.has('access-control-allow-origin')) {
    c.res.headers.delete('access-control-allow-credentials')
  }
})
app.use(
  '*',
  cors({
    origin: (origin) => (getAllowedOrigins().includes(origin) ? origin : null),
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Authorization', 'Content-Type'],
    maxAge: 600,
    credentials: true,
  }),
)

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

// ALcore wiring (identity-only Auth Repo C; generated boilerplate above untouched).
app.get('/health', (c) => {
  return c.json({ ok: true, service: 'auth-service' })
})
// Task 26: readiness with real substrate checks (config + store + signer).
// Same /health + /health/ready contract the staging runbook health-gates.
app.get('/health/ready', (c) => {
  const r = authReadiness()
  const body = r.ready
    ? { status: 'ok' as const, checks: r.checks }
    : { status: 'unavailable' as const, checks: r.checks, reasons: r.reasons }
  return c.json(body, r.ready ? 200 : 503)
})
app.route('/auth', authRoutes)
app.route('/oidc', oidcRoutes)

function bootConfig(): { port: number; hostname: string } {
  try {
    // Fail-fast: throws naming JWT_SECRET (never its value) when missing/weak in prod.
    getJwtSecret()
    return { port: getAuthPort(), hostname: getBindHost() }
  } catch (err) {
    console.error(`[auth-service] fatal config: ${err instanceof Error ? err.message : String(err)}`)
    process.exit(1)
  }
}

const { port, hostname } = bootConfig()

if (import.meta.main) {
  console.log(`[auth-service] listening on ${hostname}:${port} (${nodeEnv()})`)
}

// Bun auto-serves this single server (fetch + port + hostname); no separate
// Bun.serve call, so the port never double-binds.
export default { fetch: app.fetch, port, hostname }
