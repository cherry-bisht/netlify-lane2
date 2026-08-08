// Out-of-band collector for the image-CDN SSRF test.
// Records the FULL inbound request the Netlify image worker makes, then returns
// a valid 1x1 PNG so the worker accepts the response (200 image/png).
// Runs on my own Netlify site -- no third-party host is used as a collector.
import { getStore } from '@netlify/blobs'

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
)

export default async (req, context) => {
  const rec = {
    ts: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: Object.fromEntries(req.headers.entries()),
    ip: context?.ip ?? null,
    geo: context?.geo ?? null,
    site: context?.site ?? null,
  }
  try {
    const store = getStore('cherry-oob')
    await store.set(`hit-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, JSON.stringify(rec, null, 2))
  } catch (e) {
    try {
      const store = getStore('cherry-oob')
      await store.set(`err-${Date.now()}`, String(e))
    } catch { /* nothing else to do */ }
  }
  const wantsJson = new URL(req.url).searchParams.get('mode') === 'json'
  if (wantsJson) {
    return new Response(JSON.stringify(rec, null, 2), {
      headers: { 'content-type': 'application/json' },
    })
  }
  return new Response(PNG, { headers: { 'content-type': 'image/png' } })
}
