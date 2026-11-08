import argparse, importlib.util, json, os, sqlite3, subprocess
from pathlib import Path
import pytest
from mitmproxy import connection, http
from mitmproxy.io import FlowWriter

REPO=Path(__file__).resolve().parents[1]
def load(name):
    s=importlib.util.spec_from_file_location(name, REPO/'skills/chromium-test/scripts'/f'{name}.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

def setup_lane(monkeypatch, tmp):
    m=load('mitm_lane')
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT',str(tmp/'absent'))
    monkeypatch.setattr(m,'can_bind_localhost',lambda _: True)
    monkeypatch.setattr(m,'wait_for_port',lambda _: True)
    monkeypatch.setattr(m,'pid_alive',lambda _: False)
    monkeypatch.setattr(m.subprocess,'Popen',lambda *a,**kw: argparse.Namespace(pid=123))
    a=argparse.Namespace(root=str(tmp/'state'),lane='logical',port=8081,mitmdump='/usr/bin/mitmdump',listen_host='127.0.0.1',proxy_host='127.0.0.1',program='New',task='newtask',account=None,account_label='newaccount',profile_dir='newprofile',run_id='newrun',agent_id='newagent',runtime_host='newhost',transport='browser',browser_profile_id=None,session_source=None)
    return m,a

def flow(path):
    c=connection.Client(peername=('127.0.0.1',1),sockname=('127.0.0.1',2),timestamp_start=1)
    f=http.HTTPFlow(c,connection.Server(address=('example.test',80)))
    f.request=http.Request.make('GET','http://example.test/owned-fixture')
    with path.open('wb') as h: FlowWriter(h).add(f)

def ix(a,tmp,override=None):
    return argparse.Namespace(root=a.root,lane=a.lane,mitmdump='/usr/bin/mitmdump',db=str(tmp/'private'/'index.sqlite'),flow_file=override,store_full_requests=True)

def test_logical_query_and_profile_attribution(monkeypatch,tmp_path):
    real_popen=subprocess.Popen
    m,a=setup_lane(monkeypatch,tmp_path)
    (tmp_path/'private').mkdir(mode=0o700)
    state=m.start_lane(a); flow(Path(state['flow_file'])); m.stop_lane(a)
    monkeypatch.setattr(m.subprocess,'Popen',real_popen)
    result=m.index_store(ix(a,tmp_path)); assert result['status']=='indexed',result
    store=load('proxy_store')
    q=argparse.Namespace(db=ix(a,tmp_path).db,program=None,lane=a.lane,run_id=None,agent_id=None,account_label=None,host=None,method=None,path=None,param=None,no_background=False,limit=25)
    logical=store.query_requests(q); q.lane=state['index_lane']; generation=store.query_requests(q)
    with sqlite3.connect(q.db) as db: row=db.execute('select lane,profile_dir from lanes').fetchone()
    print('LOGICAL_QUERY',logical['count'],'GENERATION_QUERY',generation['count'],'STORED_LANE_PROFILE',row,'EXPECTED_LOGICAL_PROFILE',(a.lane,a.profile_dir))
    assert logical['count']==1
    assert generation['count']==1
    assert row == (state['index_lane'], a.profile_dir)
    # A database made before alias support remains queryable without migration.
    with sqlite3.connect(q.db) as db:
        db.execute('DROP TABLE capture_lane_aliases')
    assert store.query_requests(q)['count'] == 1

def test_legacy_receipt_metadata_bleeds_new_owner(monkeypatch,tmp_path):
    real_popen=subprocess.Popen
    m,a=setup_lane(monkeypatch,tmp_path); (tmp_path/'private').mkdir(mode=0o700)
    old=tmp_path/'old.mitm'; flow(old)
    m.write_state(Path(a.root),a.lane,{'status':'stopped','flow_file':str(old),'program':'Old'})
    state=m.start_lane(a)
    monkeypatch.setattr(m.subprocess,'Popen',real_popen)
    result=m.index_store(ix(a,tmp_path,str(old))); assert result['status']=='indexed',result
    with sqlite3.connect(ix(a,tmp_path).db) as db: row=db.execute('select program,task,run_id,agent_id,account_label,runtime_host,transport from requests').fetchone()
    assert row==('Old',None,None,None,None,None,None)

def test_mount_disappears_after_state_before_child_open(monkeypatch,tmp_path):
    m,a=setup_lane(monkeypatch,tmp_path)
    mount=tmp_path/"mount"; (mount/"New"/"web").mkdir(parents=True)
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT",str(mount))
    mounted=[True]
    monkeypatch.setattr(m.os.path,"ismount",lambda p: mounted[0] and Path(p)==mount)
    real_write=m.write_state; swapped=[]; rel_path=[]
    def swap_after_state(root,lane,state):
        real_write(root,lane,state)
        if not swapped and state.get("status")=="starting":
            old_flow=Path(state["flow_file"]); rel=old_flow.relative_to(mount)
            mount.rename(tmp_path/"previous-mount")
            (mount/rel).parent.mkdir(parents=True)
            mounted[0]=False; swapped.append(True); rel_path.append(rel)
    monkeypatch.setattr(m,"write_state",swap_after_state)
    def child(command,**kwargs):
        Path(command[-1]).write_bytes(b"synthetic-private-flow")
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(m.subprocess,"Popen",child)
    result=m.start_lane(a)
    assert result["status"] == "capture-unavailable"
    assert not (mount/rel_path[0]).exists()
