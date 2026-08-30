#!/usr/bin/env python3
"""Node-local, resource-gated persistent Chromium provisioner.

Runs on the browser node. It leases an exact account profile, checks that
node's resources, and keeps each Chromium root inside a user-systemd unit.
It never prints CDP URLs, cookies, credentials, or auth-seed locations.
"""
from __future__ import annotations
import argparse, json, os, shutil, sqlite3, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEASE = ROOT / "browser_profile_lease.py"
CHROMIUM = ROOT / "chromium_test.py"
STATE = Path(os.environ.get("BROWSER_PROVISIONER_STATE", "~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite")).expanduser()
DEFAULT_RAM_MIB, DEFAULT_SWAP_MIB, DEFAULT_IDLE = 2048, 512, 900
MAX_TABS = 5

def emit(o, code=0): print(json.dumps(o, sort_keys=True)); raise SystemExit(code)
def now(): return time.time()
def slug(s): return ''.join(c.lower() if c.isalnum() or c in '._-' else '-' for c in s).strip('.-') or 'unknown'
def db():
 STATE.parent.mkdir(parents=True, exist_ok=True); c=sqlite3.connect(STATE); c.row_factory=sqlite3.Row
 c.execute('''CREATE TABLE IF NOT EXISTS browsers (lease_id TEXT PRIMARY KEY,browser_id TEXT UNIQUE NOT NULL,program TEXT NOT NULL,account TEXT NOT NULL,agent_id TEXT NOT NULL,run_id TEXT NOT NULL,purpose TEXT NOT NULL,unit TEXT NOT NULL,profile_dir TEXT NOT NULL,launch_file TEXT NOT NULL,state TEXT NOT NULL,tab_count INTEGER NOT NULL DEFAULT 0,last_activity REAL NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)'''); return c
def meminfo():
 d={}
 for line in Path('/proc/meminfo').read_text().splitlines():
  k,v=line.split(':',1); d[k]=int(v.strip().split()[0])//1024
 return d.get('MemAvailable',0),d.get('SwapFree',0)
def admission(ram, swap):
 a,b=meminfo(); return {'status':'admitted' if a>=ram and b>=swap else 'rejected','ram_available_mib':a,'swap_free_mib':b,'required_ram_available_mib':ram,'required_swap_free_mib':swap}
def lease(args, *parts):
 p=subprocess.run([sys.executable,str(LEASE),'--json',*parts],capture_output=True,text=True)
 try: return json.loads(p.stdout)
 except Exception: return {'status':'lease-error','detail':p.stderr.strip() or p.stdout.strip()}
def sysenv():
 e=os.environ.copy(); e['XDG_RUNTIME_DIR']=f'/run/user/{os.getuid()}'; e['DBUS_SESSION_BUS_ADDRESS']=f"unix:path={e['XDG_RUNTIME_DIR']}/bus"; return e
def unit_active(unit):
 p=subprocess.run(['systemctl','--user','is-active','--quiet',unit],env=sysenv()); return p.returncode==0
def stop_unit(unit):
 subprocess.run(['systemctl','--user','stop',unit],env=sysenv(),check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['systemctl','--user','reset-failed',unit],env=sysenv(),check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def safe(row): return {k:row[k] for k in ('browser_id','lease_id','program','account','state','tab_count','last_activity','created','updated')}
def release_lease(lease_id, agent, disp='cancelled', health='unknown'): return lease(None,'release','--lease-id',lease_id,'--agent-id',agent,'--disposition',disp,'--profile-health',health)
def profile_path(program,account): return Path(os.environ.get('HARNESS_BOUNTY_ARTIFACT_ROOT','/mnt/bounty'))/slug(program)/'web'/'browser-profiles'/slug(account)
def start(args):
 # Existing owner may resume only its own stopped profile.
 # Serialized automatic retention sweep runs before every new admission.
 c=db(); sweep_rows(c,14,True); row=c.execute('select * from browsers where program=? and account=? order by created desc limit 1',(slug(args.program),slug(args.account))).fetchone()
 if row and row['agent_id']==args.agent_id and row['run_id']==args.run_id and row['state']=='running' and unit_active(row['unit']): emit({'status':'already-running',**safe(row)})
 # Capacity is an admission gate, not a lease outcome. Do not acquire a profile
 # until this node can actually start Chromium: a no-capacity retry must leave
 # the next profile user with a healthy, available profile.
 adm=admission(args.min_ram_available_mib,args.min_swap_free_mib)
 if adm['status']!='admitted': emit({'status':'queued','reason':'no-capacity','retry_after_seconds':30,'admission':adm},2)
 got=lease(args,'acquire',args.program,args.account,'--agent-id',args.agent_id,'--run-id',args.run_id,'--purpose',args.purpose,'--ttl-seconds',str(args.ttl_seconds))
 if got.get('status') not in ('leased','already-owned'): emit(got,2)
 lid=got['lease']['lease_id']
 prof=profile_path(args.program, got['lease'].get('account_alias',args.account)); bid=(row['browser_id'] if row and row['agent_id']==args.agent_id and row['run_id']==args.run_id else str(uuid.uuid4()))
 unit='browser-'+bid; launch=STATE.parent/(bid+'.launch.json'); launch.parent.mkdir(parents=True,exist_ok=True); os.chmod(launch.parent,0o700)
 # The unit stays foreground via sleep; Chromium remains inside its cgroup.
 cmd=[sys.executable,str(CHROMIUM),args.program,args.purpose,'--account',args.account,'--profile-dir',str(prof),'--run-id',args.run_id,'--agent-id',args.agent_id,'--account-label',args.account,'--proxy-cert-mode',args.proxy_cert_mode,'--json']
 if args.proxy_server: cmd += ['--proxy-server',args.proxy_server]
 if args.mitm_ca_cert: cmd += ['--mitm-ca-cert',args.mitm_ca_cert]
 if args.url: cmd += ['--url',args.url]
 if args.display_backend: cmd += ['--display-backend',args.display_backend]
 if args.kasmvnc_display is not None: cmd += ['--kasmvnc-display',str(args.kasmvnc_display)]
 if args.kasmvnc_web_port is not None: cmd += ['--kasmvnc-web-port',str(args.kasmvnc_web_port)]
 shell=f"umask 077; BROWSER_PROVISIONER_UNIT={unit}.service {' '.join(__import__('shlex').quote(x) for x in cmd)} > {__import__('shlex').quote(str(launch))}; rc=$?; test $rc -eq 0 || exit $rc; exec sleep infinity"
 run=['systemd-run','--user','--unit='+unit,'--property=MemoryHigh='+args.memory_high,'--property=MemoryMax='+args.memory_max,'--property=CPUWeight=100','--','/bin/bash','-lc',shell]
 p=subprocess.run(run,capture_output=True,text=True,env=sysenv())
 if p.returncode or not unit_active(unit): release_lease(lid,args.agent_id); emit({'status':'launch-failed','detail':(p.stderr or p.stdout).strip()},2)
 deadline=time.time()+8
 while time.time()<deadline and (not launch.exists() or launch.stat().st_size == 0): time.sleep(.2)
 try: info=json.loads(launch.read_text())
 except Exception:
  stop_unit(unit); release_lease(lid,args.agent_id); emit({'status':'launch-failed','detail':'launcher did not produce a valid private record'},2)
 reg=lease(args,'register-browser','--lease-id',lid,'--agent-id',args.agent_id,'--cdp-url',info['cdp_url'],'--service-unit',unit)
 if reg.get('status') not in ('registered','registered-unreachable'):
  stop_unit(unit); release_lease(lid,args.agent_id); emit({'status':'launch-failed','detail':'could not register owned browser'},2)
 t=now(); c.execute('delete from browsers where lease_id=?',(lid,)); c.execute('insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(lid,bid,slug(args.program),slug(got['lease'].get('account_alias',args.account)),args.agent_id,args.run_id,args.purpose,unit,str(prof),str(launch),'running',0,t,t,t)); c.commit(); out=c.execute('select * from browsers where lease_id=?',(lid,)).fetchone(); emit({'status':'started',**safe(out),'profile_lifetime':'persistent','idle_deadline_at':t+args.idle_seconds})
def touch(args):
 c=db(); r=c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone()
 if not r or r['agent_id']!=args.agent_id: emit({'status':'not-owner'},2)
 q=lease(args,'renew','--lease-id',args.lease_id,'--agent-id',args.agent_id,'--ttl-seconds',str(args.ttl_seconds),'--work-state',args.work_state)
 if q.get('status')!='renewed': emit(q,2)
 c.execute('update browsers set last_activity=?,updated=? where lease_id=?',(now(),now(),args.lease_id)); c.commit(); emit({'status':'touched',**safe(c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone())})
def status(args):
 c=db(); r=c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone()
 if not r or r['agent_id']!=args.agent_id: emit({'status':'not-owner'},2)
 running = r['state']=='running' and unit_active(r['unit'])
 if r['state']=='running' and not running:
  c.execute("update browsers set state='unknown',updated=? where lease_id=?",(now(),args.lease_id)); c.commit(); r=c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone()
 emit({'status':'ok',**safe(r),'unit_active':running,'max_tabs':MAX_TABS})
def reap(args):
 c=db(); cutoff=now()-args.idle_seconds; stopped=[]
 for r in c.execute("select * from browsers where state='running' and last_activity<?",(cutoff,)).fetchall():
  if unit_active(r['unit']): stop_unit(r['unit'])
  c.execute("update browsers set state='idle-stopped',updated=? where lease_id=?",(now(),r['lease_id'])); stopped.append(r['browser_id'])
 c.commit(); emit({'status':'ok','idle_stopped':stopped})
def release(args):
 c=db(); r=c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone()
 if not r or r['agent_id']!=args.agent_id: emit({'status':'not-owner'},2)
 stop_unit(r['unit']); Path(r['launch_file']).unlink(missing_ok=True); q=release_lease(args.lease_id,args.agent_id,args.disposition,args.profile_health)
 if q.get('status')!='released': emit(q,2)
 c.execute("update browsers set state='stopped',updated=? where lease_id=?",(now(),args.lease_id)); c.commit(); emit({'status':'released',**safe(c.execute('select * from browsers where lease_id=?',(args.lease_id,)).fetchone())})
def managed_root(): return Path(os.environ.get('HARNESS_BOUNTY_ARTIFACT_ROOT','/mnt/bounty')).resolve()
def managed_profile(path):
 try:
  relative=Path(path).resolve().relative_to(managed_root())
 except ValueError: return False
 # Only manager-shaped <program>/web/browser-profiles/<account> directories qualify.
 return len(relative.parts)==4 and relative.parts[1:3]==('web','browser-profiles') and all(part not in ('','.','..') for part in relative.parts)
def sweep_rows(c, older_than_days, confirm):
 cutoff=now()-older_than_days*86400; removed=[]; skipped=[]
 # The table is the explicit manager-created profile manifest: never discover arbitrary paths.
 for r in c.execute("select * from browsers where state='stopped' and updated<?",(cutoff,)).fetchall():
  p=Path(r['profile_dir'])
  if not managed_profile(p): skipped.append({'browser_id':r['browser_id'],'reason':'not-managed-profile'}); continue
  if unit_active(r['unit']): skipped.append({'browser_id':r['browser_id'],'reason':'unit-active'}); continue
  if not p.exists(): skipped.append({'browser_id':r['browser_id'],'reason':'already-absent'}); continue
  if not confirm: removed.append({'browser_id':r['browser_id'],'profile_dir':str(p),'dry_run':True}); continue
  shutil.rmtree(p); c.execute("update browsers set state='deleted',updated=? where lease_id=?",(now(),r['lease_id'])); removed.append({'browser_id':r['browser_id'],'profile_dir':str(p),'dry_run':False})
 c.commit(); return removed,skipped
def sweep(args):
 removed,skipped=sweep_rows(db(),args.older_than_days,args.confirm)
 emit({'status':'ok','removed':removed,'skipped':skipped})
def request(args):
 deadline=now()+args.wait_seconds; delay=30; attempts=0
 while True:
  cmd=[sys.executable,str(Path(__file__).resolve()),'start',args.program,args.account,'--agent-id',args.agent_id,'--run-id',args.run_id,'--purpose',args.purpose,'--ttl-seconds',str(args.ttl_seconds),'--idle-seconds',str(args.idle_seconds),'--min-ram-available-mib',str(args.min_ram_available_mib),'--min-swap-free-mib',str(args.min_swap_free_mib),'--memory-high',args.memory_high,'--memory-max',args.memory_max,'--proxy-cert-mode',args.proxy_cert_mode]
  if args.proxy_server: cmd += ['--proxy-server',args.proxy_server]
  if args.mitm_ca_cert: cmd += ['--mitm-ca-cert',args.mitm_ca_cert]
  if args.url: cmd += ['--url',args.url]
  if args.display_backend: cmd += ['--display-backend',args.display_backend]
  if args.kasmvnc_display is not None: cmd += ['--kasmvnc-display',str(args.kasmvnc_display)]
  if args.kasmvnc_web_port is not None: cmd += ['--kasmvnc-web-port',str(args.kasmvnc_web_port)]
  p=subprocess.run(cmd,capture_output=True,text=True)
  try: result=json.loads(p.stdout)
  except Exception: emit({'status':'launch-failed','detail':'provisioner returned invalid JSON'},2)
  attempts += 1
  if result.get('status') != 'queued': result.update({'attempts':attempts,'waited_seconds':args.wait_seconds-max(0,deadline-now())}); emit(result,p.returncode)
  remaining=deadline-now()
  if remaining <= 0: result.update({'status':'queued-timeout','attempts':attempts,'waited_seconds':args.wait_seconds,'next_retry_after_seconds':min(delay,300)}); emit(result,2)
  sleep_for=min(float(result.get('retry_after_seconds',delay)),delay,remaining)
  time.sleep(max(1,sleep_for)); delay=min(delay*2,120)
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
 a=sub.add_parser('admission'); a.add_argument('--min-ram-available-mib',type=int,default=DEFAULT_RAM_MIB); a.add_argument('--min-swap-free-mib',type=int,default=DEFAULT_SWAP_MIB)
 s=sub.add_parser('start'); s.add_argument('program'); s.add_argument('account'); s.add_argument('--agent-id',required=True); s.add_argument('--run-id',required=True); s.add_argument('--purpose',required=True); s.add_argument('--url'); s.add_argument('--ttl-seconds',type=int,default=1800); s.add_argument('--idle-seconds',type=int,default=DEFAULT_IDLE); s.add_argument('--min-ram-available-mib',type=int,default=DEFAULT_RAM_MIB); s.add_argument('--min-swap-free-mib',type=int,default=DEFAULT_SWAP_MIB); s.add_argument('--memory-high',default='1G'); s.add_argument('--memory-max',default='2G'); s.add_argument('--proxy-cert-mode',choices=('auto','import','ignore','none'),default='import'); s.add_argument('--proxy-server'); s.add_argument('--mitm-ca-cert'); s.add_argument('--display-backend',choices=('auto','default','kasmvnc')); s.add_argument('--kasmvnc-display',type=int); s.add_argument('--kasmvnc-web-port',type=int)
 r0=sub.add_parser('request'); r0.add_argument('program'); r0.add_argument('account'); r0.add_argument('--agent-id',required=True); r0.add_argument('--run-id',required=True); r0.add_argument('--purpose',required=True); r0.add_argument('--url'); r0.add_argument('--ttl-seconds',type=int,default=1800); r0.add_argument('--idle-seconds',type=int,default=DEFAULT_IDLE); r0.add_argument('--wait-seconds',type=int,default=120); r0.add_argument('--min-ram-available-mib',type=int,default=DEFAULT_RAM_MIB); r0.add_argument('--min-swap-free-mib',type=int,default=DEFAULT_SWAP_MIB); r0.add_argument('--memory-high',default='1G'); r0.add_argument('--memory-max',default='2G'); r0.add_argument('--proxy-cert-mode',choices=('auto','import','ignore','none'),default='import'); r0.add_argument('--proxy-server'); r0.add_argument('--mitm-ca-cert'); r0.add_argument('--display-backend',choices=('auto','default','kasmvnc')); r0.add_argument('--kasmvnc-display',type=int); r0.add_argument('--kasmvnc-web-port',type=int)
 t=sub.add_parser('touch'); t.add_argument('--lease-id',required=True); t.add_argument('--agent-id',required=True); t.add_argument('--ttl-seconds',type=int,default=1800); t.add_argument('--work-state',choices=('active','awaiting-input'),default='active')
 q=sub.add_parser('status'); q.add_argument('--lease-id',required=True); q.add_argument('--agent-id',required=True)
 r=sub.add_parser('reap-idle'); r.add_argument('--idle-seconds',type=int,default=DEFAULT_IDLE)
 w=sub.add_parser('sweep-stale'); w.add_argument('--older-than-days',type=int,default=14); w.add_argument('--confirm',action='store_true')
 x=sub.add_parser('release'); x.add_argument('--lease-id',required=True); x.add_argument('--agent-id',required=True); x.add_argument('--disposition',choices=('completed','handoff','cancelled'),required=True); x.add_argument('--profile-health',choices=('healthy','needs-refresh','needs-cleanup','unknown'),required=True)
 args=p.parse_args();
 if args.cmd=='admission': emit(admission(args.min_ram_available_mib,args.min_swap_free_mib),0)
 if args.cmd=='start': start(args)
 if args.cmd=='request': request(args)
 if args.cmd=='touch': touch(args)
 if args.cmd=='status': status(args)
 if args.cmd=='reap-idle': reap(args)
 if args.cmd=='sweep-stale': sweep(args)
 if args.cmd=='release': release(args)
if __name__=='__main__': main()
