#!/usr/bin/env bash
# End-to-end market-readiness QA for procellbiologics.com against the running app.
set -uo pipefail
BASE="http://localhost:5050"
PY=python

tok() { curl -s -X POST "$BASE/api/auth/login" -H "content-type: application/json" \
  -d '{"email":"auth-shared@e2e.local","password":"TestPassword123!"}' \
  | $PY -c "import sys,json;print(json.load(sys.stdin)['token'])"; }

TOKEN=$(tok); AUTH="Authorization: Bearer $TOKEN"
WSID=$(curl -s "$BASE/api/workspaces" -H "$AUTH" | $PY -c "import sys,json;d=json.load(sys.stdin);L=d if isinstance(d,list) else d.get('data',[]);print(next((w['id'] for w in L if (w.get('name') or '').lower()=='procellbiologics.com'),''))")
echo "[qa] workspace=$WSID"

echo "[qa] waiting for the running scan to complete..."
for i in $(seq 1 80); do
  ST=$(curl -s "$BASE/api/workspaces/$WSID/scans" -H "$AUTH" | $PY -c "import sys,json;d=json.load(sys.stdin);L=d if isinstance(d,list) else d.get('data',[]);r=[s for s in L if s.get('status') in ('running','pending','queued')];print((r[0]['status']+' '+str(r[0].get('progressPercent',0))+'% '+str(r[0].get('currentStep',''))) if r else 'DONE')")
  echo "[qa] $(date +%H:%M:%S) scan: $ST"
  [ "$ST" = "DONE" ] && break
  sleep 30
done

echo "[qa] === FINDINGS QA ==="
curl -s "$BASE/api/workspaces/$WSID/findings" -H "$AUTH" | $PY -c "
import sys,json
d=json.load(sys.stdin); L=d if isinstance(d,list) else d.get('data',[])
from collections import Counter
c=Counter((f.get('severity') or 'info').lower() for f in L)
print('total findings:', len(L))
print('by severity:', dict(c))
titles=[ (f.get('title') or '') for f in L ]
def has(sub): return any(sub.lower() in t.lower() for t in titles)
print('WordPress user enumeration present:', has('user') and (has('enumeration') or has('administrator')))
print('DB/MySQL exposure present:', has('mysql') or has('database service'))
print('S3 false-positive present (should be False):', any('s3' in t.lower() and 'bucket' in t.lower() for t in titles))
print('XSS finding present:', has('xss') or has('cross-site scripting'))
print('sample titles:')
for t in titles[:18]: print('   -', t[:78])
"

echo "[qa] === REPORT + DOCX ==="
REP=$(curl -s -X POST "$BASE/api/workspaces/$WSID/reports" -H "$AUTH" -H "content-type: application/json" \
  -d "{\"title\":\"Procell Market-Ready QA\",\"type\":\"full_report\",\"workspaceId\":\"$WSID\"}" | $PY -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "[qa] report id=$REP"
for i in $(seq 1 20); do
  RS=$(curl -s "$BASE/api/reports/$REP" -H "$AUTH" | $PY -c "import sys,json;print(json.load(sys.stdin).get('status'))")
  [ "$RS" = "completed" ] && break; sleep 2
done
echo "[qa] report status: $RS"

curl -s "$BASE/api/workspaces/$WSID/reports/$REP/export?format=docx" -H "$AUTH" -o "$OUTDIR/qa-procell.docx"
echo "[qa] plain docx bytes: $(stat -c%s "$OUTDIR/qa-procell.docx" 2>/dev/null) (PK=$(head -c2 "$OUTDIR/qa-procell.docx"))"
echo "[qa] capturing evidence docx (Chromium)..."
curl -s "$BASE/api/workspaces/$WSID/reports/$REP/export?format=docx&evidence=1" -H "$AUTH" -o "$OUTDIR/qa-procell-evidence.docx"
echo "[qa] evidence docx bytes: $(stat -c%s "$OUTDIR/qa-procell-evidence.docx" 2>/dev/null) (PK=$(head -c2 "$OUTDIR/qa-procell-evidence.docx"))"
echo "[qa] DONE"
