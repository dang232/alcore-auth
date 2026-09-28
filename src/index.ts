import { Hono } from 'hono'
import { authRoutes } from './routes/auth'
import { oidcRoutes } from './routes/oidc'
import { getAuthPort, getBindHost, getJwtSecret, nodeEnv } from './config'
import { authReadiness } from './lib/readiness'

export const app = new Hono()

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
