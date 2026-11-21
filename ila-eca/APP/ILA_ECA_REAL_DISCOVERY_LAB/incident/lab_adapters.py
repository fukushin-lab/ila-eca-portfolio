"""Explicit local-LAB product connections. No discovery from model text."""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep, perf_counter
from urllib.parse import urlsplit, urlencode
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
import base64,json,re,socket,subprocess

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import ReadOperation


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise PermissionError('LAB_PRODUCT_REDIRECT_DENIED')


def http_json(url,*,method='GET',body=None,headers=None,timeout=10,max_bytes=2_000_000):
    parsed=urlsplit(url)
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.username or parsed.password or parsed.fragment:
        raise PermissionError('LAB_EXACT_LOOPBACK_ENDPOINT_REQUIRED')
    req=Request(url,data=json.dumps(body).encode() if body is not None else None,
                headers={'Accept':'application/json','Content-Type':'application/json',**(headers or {})},method=method)
    start=perf_counter()
    try:
        response=build_opener(ProxyHandler({}),NoRedirect()).open(req,timeout=timeout)
    except HTTPError as exc:
        response=exc
    with response:
        raw=response.read(max_bytes+1)
        if len(raw)>max_bytes:
            raise ValueError('LAB_PRODUCT_RESPONSE_OVER_LIMIT_NO_TRUNCATION')
        if headers and any(value.encode() in raw for value in headers.values() if len(value)>24):
            raise PermissionError('LAB_PRODUCT_CREDENTIAL_ECHO_DENIED')
        try:
            value=json.loads(raw)
        except (ValueError,UnicodeError):
            value={'non_json_body_sha256':sha256(raw).hexdigest()}
        return {'status':response.code,'body':value,'response_sha256':sha256(raw).hexdigest(),
                'observed_at':utc_now(),'elapsed_seconds':perf_counter()-start}


class LocalCluster:
    def __init__(self,*,kubectl,kubeconfig,context,server,namespace,owner_label,owner_value,runner=None):
        self.kubectl=str(Path(kubectl).resolve(strict=True))
        self.kubeconfig=Path(kubeconfig).resolve(strict=True)
        self.config_sha=sha256(self.kubeconfig.read_bytes()).hexdigest()
        if not context.startswith('kind-') or not re.fullmatch(r'https://127\.0\.0\.1:[0-9]{1,5}',server):
            raise PermissionError('LOCAL_KIND_TARGET_REQUIRED_NO_AWS')
        if not re.fullmatch(r'ila-eca-[a-z0-9-]{3,50}',namespace) or not owner_label or not owner_value:
            raise PermissionError('DEDICATED_OWNED_LAB_NAMESPACE_REQUIRED')
        self.context=context;self.server=server;self.namespace=namespace
        self.owner_label=owner_label;self.owner_value=owner_value
        self.runner=runner or subprocess.run
        self.validate_context()

    def command(self,args,*,input_bytes=None,timeout=20):
        if sha256(self.kubeconfig.read_bytes()).hexdigest()!=self.config_sha:
            raise PermissionError('PINNED_KUBECONFIG_CHANGED')
        prefix=[self.kubectl,'--kubeconfig',str(self.kubeconfig),'--context',self.context,'--request-timeout=10s']
        return self.runner(prefix+list(args),input=input_bytes,capture_output=True,timeout=timeout,check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess,'CREATE_NO_WINDOW') else 0)

    def validate_context(self):
        result=self.command(['config','view','--minify','-o','json'])
        if result.returncode:
            raise PermissionError('LOCAL_KUBE_CONFIGURATION_UNAVAILABLE')
        view=json.loads(result.stdout)
        cluster=view['clusters'][0]['cluster']
        if cluster.get('server')!=self.server or cluster.get('insecure-skip-tls-verify'):
            raise PermissionError('PINNED_LOOPBACK_KUBE_SERVER_REQUIRED')
        # No exec-based AWS credential plugin is ever invoked by this configuration.
        if any('exec' in u.get('user',{}) or 'auth-provider' in u.get('user',{}) for u in view.get('users',[])):
            raise PermissionError('LOCAL_KUBE_EXEC_AUTH_DENIED')

    def ownership(self):
        r=self.command(['get','namespace',self.namespace,'-o','json'])
        if r.returncode or json.loads(r.stdout)['metadata'].get('labels',{}).get(self.owner_label)!=self.owner_value:
            raise PermissionError('LOCAL_LAB_NAMESPACE_OWNERSHIP_CHANGED')

    def read(self,resource,name=None):
        allowed={'deployments','pods','services','endpointslices','events','networkpolicies'}
        if resource not in allowed or (name is not None and not re.fullmatch('[a-z0-9][-a-z0-9.]{0,252}',name)):
            raise PermissionError('LOCAL_KUBE_READ_OPERATION_DENIED')
        self.validate_context();self.ownership()
        args=['-n',self.namespace,'get',resource]+([name] if name else [])+['-o','json']
        result=self.command(args)
        if result.returncode:
            text=result.stderr.decode(errors='replace')
            if 'Forbidden' in text or 'Unauthorized' in text:
                raise PermissionError('LOCAL_KUBE_READ_ACCESS_DENIED')
            raise RuntimeError('LOCAL_KUBE_READ_FAILED')
        if len(result.stdout)>2_000_000:
            raise ValueError('LOCAL_KUBE_RESPONSE_OVER_LIMIT_NO_TRUNCATION')
        return json.loads(result.stdout)

    def operation(self,operation_id,resource,target_ref,name=None):
        def read(_):
            return {'state':'OBSERVED','target_ref':target_ref,'observed_at':utc_now(),
                    'coverage':'Live named Kubernetes resource in the permitted namespace',
                    'values':{'fields':self.read(resource,name)}}
        return ReadOperation(operation_id,target_ref,f'kubernetes://{self.context}/{self.namespace}/{resource}/{name or ""}',
            f'Read {resource} in the permitted namespace',read,paths=['/values/fields'],origin='LIVE_KUBERNETES_READONLY',
            conditions={'namespace':self.namespace,'resource':resource,'name':name,'kubeconfig_sha256':self.config_sha})

    @contextmanager
    def forward(self,namespace,service,remote_port):
        if namespace!=self.namespace and namespace!='ila-eca-v28-3-awx':
            raise PermissionError('LAB_FORWARD_NAMESPACE_DENIED')
        if namespace=='ila-eca-v28-3-awx' and (service,remote_port)!=('ila-v28-awx-service',80):
            raise PermissionError('LAB_AWX_FORWARD_TARGET_DENIED')
        self.validate_context()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        args=[self.kubectl,'--kubeconfig',str(self.kubeconfig),'--context',self.context,
              '-n',namespace,'port-forward','--address','127.0.0.1','service/'+service,f'{port}:{remote_port}']
        proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess,'CREATE_NO_WINDOW') else 0)
        try:
            deadline=monotonic()+20
            while monotonic()<deadline:
                if proc.poll() is not None:raise RuntimeError('LAB_FORWARD_EXITED')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.5):break
                except OSError:sleep(.25)
            else:raise TimeoutError('LAB_FORWARD_START_TIMEOUT')
            yield port
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)


class AWXRepairAPI:
    """No setup/credential/merge APIs. One pinned template and tagged job reads."""
    execution_kind='LIVE'
    def __init__(self,port,credential,template_id,*,transport=None,verify_playbook=None):
        if type(port) is not int or not 1<=port<=65535 or type(template_id) is not int or template_id<1 or not callable(credential):
            raise ValueError('AWX_REPAIR_CONFIGURATION_INVALID')
        self.port=port;self.credential=credential;self.template_id=template_id
        self.transport=transport or http_json
        self.verify_playbook=verify_playbook
        self.calls=[]

    def request(self,method,path,body=None):
        allowed=(method=='GET' and (path==f'/api/v2/job_templates/{self.template_id}/' or
            path==f'/api/v2/job_templates/{self.template_id}/credentials/' or
            re.fullmatch(r'/api/v2/projects/[0-9]+/',path) or
            re.fullmatch(r'/api/v2/jobs/[0-9]+/',path) or path.startswith('/api/v2/jobs/?job_template='+str(self.template_id)+'&')))
        allowed=allowed or (method=='POST' and path==f'/api/v2/job_templates/{self.template_id}/launch/')
        if not allowed:
            raise PermissionError('AWX_REPAIR_API_OPERATION_DENIED')
        self.calls.append({'method':method,'path':path,'at':utc_now()})
        result=self.transport(f'http://127.0.0.1:{self.port}'+path,method=method,body=body,
            headers={'Authorization':self.credential()},timeout=30)
        if result['status'] not in {200,201,202}:
            raise PermissionError('AWX_HTTP_'+str(result['status']))
        return result['body']

    def check_template(self,target):
        row=self.request('GET',f'/api/v2/job_templates/{self.template_id}/')
        expected={k:target[k] for k in ('inventory','project','playbook','execution_environment')}
        if row.get('id')!=self.template_id or any(row.get(k)!=v for k,v in expected.items()) or row.get('ask_variables_on_launch') is not True:
            raise PermissionError('AWX_PINNED_TEMPLATE_CHANGED')
        if any(row.get(k) for k in ('ask_inventory_on_launch','ask_credential_on_launch','ask_scm_branch_on_launch')):
            raise PermissionError('AWX_DYNAMIC_EXECUTION_TARGET_DENIED')
        project=self.request('GET',f"/api/v2/projects/{target['project']}/")
        if (project.get('scm_revision')!=target.get('scm_revision')
            or project.get('scm_branch')!=target.get('scm_revision')
            or project.get('status')!='successful' or project.get('allow_override')):
            raise PermissionError('AWX_EXECUTION_PROJECT_REVISION_CHANGED')
        credentials=self.request('GET',f'/api/v2/job_templates/{self.template_id}/credentials/')['results']
        expected_credentials=target.get('credential_ids',[target['owned_awx_ids']['credential']])
        if sorted(c['id'] for c in credentials)!=sorted(expected_credentials):
            raise PermissionError('AWX_SCOPED_CREDENTIAL_CHANGED')
        if not callable(self.verify_playbook) or self.verify_playbook(target)!=target['playbook_sha256']:
            raise PermissionError('AWX_ACTUAL_PLAYBOOK_BYTES_NOT_VERIFIED')

    def launch(self,tag,spec,resource_version):
        if not re.fullmatch('ILA-ECA-[a-f0-9-]{36}',tag):
            raise ValueError('AWX_EXECUTION_TAG_INVALID')
        variables={'ila_execution_id':tag,'ila_plan_sha256':data_digest(spec),
                   'ila_resource_uid':spec['resource']['uid'],'ila_resource_version':resource_version,
                   'ila_before_selector':spec['before']['spec']['selector'],
                   'ila_after_selector':spec['after']['spec']['selector']}
        row=self.request('POST',f'/api/v2/job_templates/{self.template_id}/launch/',{'extra_vars':variables})
        if row.get('ignored_fields') or type(row.get('id',row.get('job'))) is not int:
            raise ValueError('AWX_LAUNCH_PARAMETERS_NOT_ACCEPTED')
        return row.get('id',row.get('job'))

    def job(self,job_id):
        if type(job_id) is not int or job_id<=0:raise ValueError('AWX_JOB_ID_REQUIRED')
        row=self.request('GET',f'/api/v2/jobs/{job_id}/')
        value={k:row.get(k) for k in ('id','status','job_template','started','finished','elapsed','failed','scm_revision')}
        variables=row.get('extra_vars',{})
        if isinstance(variables,str):variables=json.loads(variables)
        value['extra_vars']={k:variables.get(k) for k in ('ila_execution_id','ila_plan_sha256')}
        return value

    def find_jobs(self,tag):
        rows=[];page=1
        while True:
            query=urlencode({'job_template':self.template_id,'order_by':'-id','page_size':100,'page':page})
            data=self.request('GET','/api/v2/jobs/?'+query)
            for row in data['results']:
                variables=row.get('extra_vars',{})
                if isinstance(variables,str):variables=json.loads(variables)
                if variables.get('ila_execution_id')==tag:
                    rows.append(self.job(row['id']))
            if not data.get('next'):return rows
            page+=1
            if page>10:raise ValueError('AWX_RECONCILIATION_PAGINATION_INCOMPLETE')
