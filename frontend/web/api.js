// Versioned transport boundary. Backend-specific data adaptation belongs in local_api/adapter.py.
const base='/api/v1';
let token='';
export async function connect(){
  const response=await fetch(base+'/health',{cache:'no-store'});
  if(!response.ok)throw new Error('The local service could not be reached.');
  const health=await response.json();token=health.token;return health;
}
async function request(path,options={},blob=false){
  const response=await fetch(base+path,{...options,cache:'no-store',headers:{'X-SilentSec-Token':token,...options.headers}});
  if(!response.ok){let data;try{data=await response.json()}catch{}throw new Error(data?.error||`Request failed (${response.status}).`)}
  return blob?response.blob():response.json();
}
export const listJobs=()=>request('/jobs');
export const getJob=id=>request('/jobs/'+encodeURIComponent(id));
export const result=id=>request('/jobs/'+encodeURIComponent(id)+'/result');
export const report=id=>request('/jobs/'+encodeURIComponent(id)+'/report',{},true);
export const start=(operation,args)=>request('/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operation,args})});
export const context=(job_id,fingerprint)=>request('/context',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id,fingerprint})});

export const sarif=id=>request('/jobs/'+encodeURIComponent(id)+'/sarif',{},true);
