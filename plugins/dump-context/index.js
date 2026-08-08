// Local build plugin. Reports the SHAPE of what the plugin API hands to build
// plugin code, and whether any credential reaches it in-process.
// Token VALUES are never printed -- only location, length and a sha256 prefix.
const crypto = require('crypto')
const fs = require('fs')

const h = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16)

// JWT-shaped or long opaque credential
const looksLikeCred = (v) =>
  typeof v === 'string' &&
  ((/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(v)) ||
   (/^(nfp_|eyJ)/.test(v)) ||
   (v.length >= 64 && /^[A-Za-z0-9+/=_-]+$/.test(v)))

function walk (node, path, out, seen, depth) {
  if (depth > 6 || node == null) return
  if (typeof node === 'string') {
    if (looksLikeCred(node)) {
      let claims = null
      const parts = node.split('.')
      if (parts.length === 3) {
        try { claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) } catch (e) {}
        if (claims && claims.netlify_auth_token) claims.netlify_auth_token = '<withheld>'
      }
      out.push({ path, len: node.length, sha256: h(node), claims })
    }
    return
  }
  if (typeof node !== 'object') return
  if (seen.has(node)) return
  seen.add(node)
  for (const k of Object.keys(node)) {
    let v
    try { v = node[k] } catch (e) { continue }
    walk(v, path ? `${path}.${k}` : k, out, seen, depth + 1)
  }
}

const report = (event, opts) => {
  const lines = []
  lines.push(`### ${event} ###`)
  lines.push(`  top-level keys: ${Object.keys(opts).sort().join(' ')}`)
  lines.push(`  extensionMetadata present: ${opts.extensionMetadata ? 'YES' : 'no'}`)
  if (opts.extensionMetadata) {
    lines.push(`  extensionMetadata keys: ${Object.keys(opts.extensionMetadata).join(' ')}`)
  }
  const found = []
  walk(opts, '', found, new WeakSet(), 0)
  lines.push(`  credential-shaped values reachable from plugin args: ${found.length}`)
  for (const f of found) {
    lines.push(`    at ${f.path}  len=${f.len}  sha256=${f.sha256}`)
    if (f.claims) lines.push(`       claims: ${JSON.stringify(f.claims)}`)
  }
  const txt = lines.join('\n') + '\n'
  console.log(txt)
  try { fs.appendFileSync('/tmp/plugin-dump.txt', txt) } catch (e) {}
}

module.exports = {
  onPreBuild: (opts) => report('onPreBuild', opts),
  onBuild: (opts) => report('onBuild', opts),
  onPostBuild: (opts) => report('onPostBuild', opts)
}
