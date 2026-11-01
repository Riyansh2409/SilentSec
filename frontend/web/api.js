// Versioned transport boundary. Backend-specific data adaptation belongs in local_api/adapter.py.
export const platform=document.documentElement.dataset.platform==='true';
const base=platform?'/api/v1/workstation':'/api/v1';
let token='',csrf='';
export async function connect(){
  if(platform){const response=await fetch('/api/v1/auth/me',{cache:'no-store'});if(response.status===401){location.assign('/login');throw new Error('Sign in required.');}if(!response.ok)throw new Error('Account unavailable.');const me=await response.json();csrf=me.csrf_token;const health=await request('/health');health.identity=me;return health;}
  const response=await fetch(base+'/health',{cache:'no-store'});
  if(!response.ok)throw new Error('The local service could not be reached.');
  const health=await response.json();token=health.token;return health;
}
async function request(path,options={},blob=false){
  const response=await fetch(base+path,{...options,cache:'no-store',headers:{'X-SilentSec-Token':token,...(platform?{'X-CSRF-Token':csrf,'Idempotency-Key':crypto.randomUUID()}:{}),...options.headers}});
  if(response.status===401&&platform){location.assign('/login');throw new Error('Sign in again to continue.');}
  if(!response.ok){const data=await response.json().catch(()=>({}));const detail=data.detail;throw new Error(data.error||(typeof detail==='string'?detail:detail?.message||detail?.code)||`Request failed (${response.status}).`);}
  return blob?response.blob():response.json();
}
export const listJobs=()=>request('/jobs');
export const getJob=id=>request('/jobs/'+encodeURIComponent(id));
export const result=id=>request('/jobs/'+encodeURIComponent(id)+'/result');
export const report=id=>request('/jobs/'+encodeURIComponent(id)+'/report',{},true);
export async function start(operation,args){
  if(platform&&['upload','verify_upload'].includes(operation)){
    const {content,filename,...rest}=args;
    const bytes=Uint8Array.from(atob(content),c=>c.charCodeAt(0));
    const form=new FormData();form.append('file',new Blob([bytes]),filename);form.append('metadata',JSON.stringify({operation,args:rest}));
    return request('/upload',{method:'POST',body:form});
  }
  return request('/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operation,args})});
}
export const context=(job_id,fingerprint)=>request('/context',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id,fingerprint})});

export const sarif=id=>request('/jobs/'+encodeURIComponent(id)+'/sarif',{},true);
export const cancel=id=>fetch('/api/v1/scans/'+encodeURIComponent(id)+'/cancel',{method:'POST',headers:{'X-CSRF-Token':csrf,'Idempotency-Key':crypto.randomUUID()}}).then(async response=>{if(!response.ok)throw new Error('Cancellation could not be requested.');return response.json();});
