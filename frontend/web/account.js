import {api,setMe,node,link,button} from '/assets/shared.js';
import {usagePage,settings} from '/assets/workspace.js';
export async function mountAccount(health){
  setMe(health.identity);
  const bar=document.getElementById('account-bar');if(!bar)return;
  bar.replaceChildren();
  const identity=health.identity,usage=health.platform.usage;document.querySelector('[data-view=account]').hidden=!['owner','admin'].includes(identity.organization_role);
  const label=node('label','Organization'),select=node('select');select.setAttribute('aria-label','Active organization');
  for(const org of identity.organizations){const option=node('option',org.name);option.value=org.id;option.selected=org.id===identity.active_organization;select.append(option);}
  label.append(select);select.addEventListener('change',async()=>{try{await api('/auth/organization/'+select.value,{method:'POST'});location.reload();}catch(error){bar.append(node('p',error.message,'notice error'));}});
  const plan=link(usage.plan==='free'?`${usage.credits_left} of 30 credits left`:`${usage.plan} · fair-use limits`,'#usage','account-credits');
  const signout=button('Sign out',async()=>{await api('/auth/logout',{method:'POST'});location.assign('/login');},'button quiet');
  bar.append(label,plan,node('span',identity.user.email,'note'),signout);
  if(identity.platform_roles.includes('platform_admin'))bar.append(link('Admin ↗','/admin/login','button quiet'));
  const input=document.getElementById('repo-path'),roots=health.platform.repositories;
  document.getElementById('registered-repositories')?.remove();const choices=node('datalist');choices.id='registered-repositories';roots.forEach(r=>{const option=node('option');option.value=r.path;option.label=r.name;choices.append(option);});input.after(choices);input.setAttribute('list',choices.id);
  if(!input.value&&roots.length)input.value=roots[0].path;
  document.getElementById('repo-help').textContent='Use a repository registered locally for this organization. GitHub and uploads are available in their own tab.';
}
export async function renderAccount(view,name){
  const section=node('div',null,'account-content');view.append(section);
  try{if(name==='usage'){
    await usagePage(section);
    const operations=await api('/workstation/jobs');const ids=new Set(operations.jobs.map(j=>j.id));
    section.querySelectorAll('a[href^="#scan/"]').forEach(a=>{a.href=ids.has(a.hash.split('/')[1])?'#operation/'+a.hash.split('/')[1]:'/account'+a.hash;});
    const health=await fetch('/api/v1/workstation/health',{cache:'no-store'}).then(r=>r.json());
    const panel=node('section',null,'card');panel.append(node('h2','Separate operation allowances'));
    for(const quota of health.platform.quotas)panel.append(node('p',`${quota.operation.replaceAll('_',' ')}: ${quota.used} reserved or used / ${quota.limit} this month`,'fine'));
    panel.append(node('p','Verification, PR checks, history commits and AI findings never silently use standard scan credits. A fresh scan or report uses one standard scan unit.','fine'));section.append(panel);
  }else await settings(section);}catch(error){section.append(node('p',error.message,'notice error'));}
}
