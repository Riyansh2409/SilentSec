import {scanIncomplete,reintroducedChanges,returnedCount,findingTags,mergeInfo,exposureOf,aiDisclosure,scoredView,nativeIssueView,triageAttributionText,cleanRepoPath,aiHasExternal,scopeLines} from './data.js';
import * as api from './api.js';
import {debtViews} from './debt-views.js';

const $=id=>document.getElementById(id);
const state={health:null,view:'overview',jobs:[],busy:null,results:{},fixMode:'ai',selectedFingerprint:'',detailSequence:0};
const titles={overview:['Your code. In focus.','Scan a local repository and inspect what the backend finds.'],findings:['Follow the evidence.','Inspect source locations, scanner observations, and optional AI explanations.'],fixes:['Review the change.','Propose a fix or verify a patch in a separate copy of your repository.'],history:['Debt leaves a trail.','See how findings and debt changed across your Git commits.'],reports:['Keep the evidence.','Generate the backend’s self-contained HTML report for review.']};
titles.sources=['Bring your repository.','Scan a public GitHub repository, a ZIP archive, or one source file using the backend’s native API.'];
titles.gate=['Check the change.','Compare two Git revisions. Existing issues do not block the change.'];
const labels={gate:'PR check',sources:'GitHub / upload',overview:'Overview',findings:'Findings',fixes:'Fix review',history:'Time Machine',reports:'Reports'};
const ranks={critical:0,high:1,medium:2,low:3,info:4};
const text=value=>value==null?'—':String(value);
const human=value=>text(value).replaceAll('_',' ');
const number=value=>typeof value==='number'&&Number.isFinite(value)?new Intl.NumberFormat(undefined,{maximumFractionDigits:2}).format(value):'—';
function el(tag,className='',content){const node=document.createElement(tag);if(className)node.className=className;if(content!=null)node.textContent=String(content);return node}
function append(parent,...children){for(const child of children.flat())if(child)parent.append(child);return parent}
function button(label,handler,style='secondary'){const b=el('button','button '+style,label);b.type='button';b.addEventListener('click',handler);return b}
function badge(value){const safe=String(value||'unknown').replace(/[^a-z_]/g,'');return el('span','badge '+safe,human(value))}
function panel(title){const p=el('section','panel');if(title)p.append(el('h2','',title));return p}
function note(message){return el('p','note',message)}
function aiNotice(config){const text=aiDisclosure(config);return aiHasExternal(config)?el('div','notice',text):note(text)}
function notice(message,type=''){const n=$('notice');n.className='notice '+type;n.textContent=message;n.hidden=!message}
function empty(title,description,symbol='◈'){return append(el('div','empty'),el('div','empty-symbol',symbol),el('h2','',title),el('p','',description))}
function list(items){const ul=el('ul','list');for(const item of items||[])ul.append(el('li','',item));return ul}
function sectionHead(title,action){return append(el('div','panel-head'),el('h2','',title),action)}
function check(id,label,description='',checked=false){const wrapper=el('label','check');const input=el('input');input.type='checkbox';input.id=id;input.checked=checked;const span=el('span','',label);if(description)span.append(el('small','',description));wrapper.append(input,span);return{wrapper,input}}
function field(id,label,type='number',value=180,min=1,max=600){const wrapper=el('div','field'),lab=el('label','',label),input=el('input');lab.htmlFor=id;input.id=id;input.type=type;input.value=value;if(type==='number'){input.min=min;input.max=max;input.step=1}wrapper.append(lab,input);return{wrapper,input}}
function select(id,label,options){const wrapper=el('div','field'),lab=el('label','',label),input=el('select');lab.htmlFor=id;input.id=id;for(const [value,title]of options){const o=el('option','',title);o.value=value;input.append(o)}wrapper.append(lab,input);return{wrapper,input}}
function checked(id){return !!$(id)?.checked}
function numeric(id,fallback){return $(id)?Number($(id).value):fallback}
function repo(){const value=cleanRepoPath($('repo-path').value);$('repo-path').value=value;if(!value){$('repo-path').focus();throw new Error('Enter your local repository folder first.')}return value}
function sameRepo(path){return String(path).replaceAll('\\','/').replace(/\/$/,'').toLowerCase()===cleanRepoPath($('repo-path').value).replaceAll('\\','/').replace(/\/$/,'').toLowerCase()}
function current(kind){const result=state.results[kind];return result&&sameRepo(result.job.repo_path)?result:null}
function operationButton(label,handler,operation){const b=button(label,handler,'');b.dataset.operation=operation;updateButton(b);return b}
function updateButton(b){b.disabled=(b.dataset.operation==='fix'&&!state.health?.backend?.ai_configured)||!!state.busy||!state.health?.backend_ready||!state.health?.backend?.capabilities?.[b.dataset.operation]}
function updateButtons(){document.querySelectorAll('[data-operation]').forEach(updateButton)}
function formatErrors(errors){return errors?.length?list(errors):null}
function saveFile(data,name,type='application/json'){const blob=data instanceof Blob?data:new Blob([data],{type});const url=URL.createObjectURL(blob);const a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000)}
function exportResult(entry){saveFile(JSON.stringify(entry.data,null,2),`silentsec-${entry.job.operation}.json`)}
function meta(entry){const row=append(el('div','result-meta'),el('span','',entry.job.repo_path),el('span','',new Date(entry.job.started_at*1000).toLocaleString()),button('Export JSON',()=>exportResult(entry),'quiet'));if(['scan','gate'].includes(entry.job.operation))row.append(button('Download SARIF',async()=>{try{saveFile(await api.sarif(entry.job.id),'silentsec.sarif')}catch(e){notice(e.message,'error')}},'quiet'),el('span','','GitHub code scanning reads SARIF.'));return row}

async function refreshJobs(){const response=await api.listJobs();state.jobs=response.jobs;const picker=$('recent-jobs');picker.replaceChildren();const placeholder=el('option','','Open a completed operation');placeholder.value='';picker.append(placeholder);for(const j of state.jobs.filter(j=>j.status==='succeeded')){const option=el('option','',`${human(j.operation)} · ${j.repo_path.split(/[\\/]/).pop()} · ${new Date(j.started_at*1000).toLocaleTimeString()}`);option.value=j.id;picker.append(option)}}
function status(message,busy=true){const area=$('job-status');area.hidden=!message;area.replaceChildren();if(message)append(area,busy?el('span','spinner'):null,el('span','',message))}
async function execute(operation,args){
  if(state.busy)return;
  try{
    notice('');state.busy={operation};updateButtons();
    const job=await api.start(operation,args);state.busy=job;if(!['github','upload','verify_github','verify_upload'].includes(operation))$('repo-path').value=job.repo_path;
    status(`${human(operation)} is running. Results will appear when the backend finishes.`);
    await poll(job.id);
  }catch(error){state.busy=null;status('');notice(error.message,'error');updateButtons()}
}
async function poll(id){
  let failures=0;
  for(;;){
    await new Promise(resolve=>setTimeout(resolve,1300));
    let job;
    try{job=await api.getJob(id);failures=0}catch(error){failures++;if(failures>=4)throw new Error('Connection to the local service was lost. The operation may still be running; refresh to reconnect.');continue}
    if(job.status==='succeeded'){
      state.busy=null;status('');await refreshJobs();await load(job);notice(`${human(job.operation)} finished. Review the backend result below.`,'success');updateButtons();return;
    }
    if(job.status==='failed'){state.busy=null;status('');await refreshJobs();throw new Error(job.error||'The operation failed.')}
    const seconds=Math.max(0,Math.floor(Date.now()/1000-job.started_at));
    status(`${human(job.operation)} ${human(job.status)} · ${seconds}s elapsed. Waiting for backend results.`);
  }
}
async function load(job){
  try{
    const data=await api.result(job.id);state.results[job.operation]={job,data};if(!['github','upload','verify_github','verify_upload'].includes(job.operation))$('repo-path').value=job.repo_path;
    const view={gate:'gate',verify_github:'fixes',verify_upload:'fixes',github:'sources',upload:'sources',scan:'overview',history:'history',fix:'fixes',verify:'fixes',report:'reports'}[job.operation];
    if(job.operation.startsWith('verify_'))state.fixMode=job.operation;
    if(job.operation==='fix'||job.operation==='verify')state.fixMode=job.operation==='fix'?'ai':'patch';
    if(location.hash.slice(1)!==view)location.hash=view;else render();
  }catch(error){notice(error.message,'error')}
}

function scanOptions(){
 const p=panel();p.append(sectionHead('Start a repository scan',operationButton('Run scan ↗',()=>{
  try{execute('scan',{repo_path:repo(),timeout:numeric('scan-timeout',180),ai_triage:checked('scan-ai'),max_ai_findings:numeric('scan-limit',20),use_cache:checked('scan-cache')})}catch(e){notice(e.message,'error')}
 },'scan')));
 p.append(note('Semgrep · Bandit · Gitleaks · Python architecture analysis. Ordinary scanning reads source files without running the project.'));
 const ai=check('scan-ai','Include AI triage','Optional: uses the configured provider order below. Cloud calls may consume API quota.');ai.input.disabled=!state.health?.backend?.ai_configured;p.append(ai.wrapper);
 p.append(aiNotice(state.health?.backend));
 const details=el('details');details.append(el('summary','','Scan options'));const grid=el('div','form-grid');append(grid,field('scan-timeout','Per-scanner timeout (seconds)').wrapper,field('scan-limit','Maximum AI findings','number',20,1,100).wrapper);append(details,grid,check('scan-cache','Reuse AI triage cache','',true).wrapper);p.append(details);return p;
}
function stat(label,value,description,suffix=''){const p=el('div','stat'),v=el('div','stat-value',value);if(suffix)v.append(el('small','',suffix));return append(p,el('div','stat-label',label),v,el('div','stat-note',description))}
function completeness(data){if(scanIncomplete(data))return el('div','notice','Incomplete scan: some scanners did not finish successfully. The score reflects available findings and does not establish that the project is clear of issues.');return null}
function renderOverview(view){
 view.append(scanOptions());const entry=current('scan');
 if(!entry){view.append(empty('Start with your repository.','Enter its local folder path above, then run a scan. Results here will come directly from your backend.'));renderReadiness(view);return}
 const d=entry.data,s=d.security_debt;append(view,meta(entry),completeness(d));
 if(!s){append(view,el('div','notice error','The backend did not produce a debt report.'),formatErrors(d.errors));return}
 const stats=el('div','stats');append(stats,stat('Security debt',number(s.score),s.raw_score>s.score?`Uncapped: ${number(s.raw_score)}`:'Higher score means more debt.','/100'),stat('Security risk',human(s.risk_level),s.risk_explanation),stat('Architecture risk',human(s.architecture_risk_level),`${number(s.architecture_debt_points)} / 25 architecture points`),stat('Unique open issues',number(s.unique_open_findings_count),`${number(s.input_findings_count)} raw findings · ${number(s.duplicate_findings_removed)} duplicates removed`));view.append(stats);
 const columns=el('div','columns'),scanners=panel('Scanner coverage'),components=panel('How the score adds up');
 for(const scanner of d.scanners||[]){const row=el('div','scanner');append(row,append(el('div','row'),el('strong','',scanner.scanner),badge(scanner.status)),note(`${scanner.findings?.length||0} findings · ${number(scanner.duration_seconds)}s`),formatErrors(scanner.errors));scanners.append(row)}
 scanners.append(note(`Total duration: ${number(d.duration_seconds)}s · Languages: ${(d.languages||[]).join(', ')||'Not detected'}`));
 for(const component of s.components||[]){const block=el('div','breakdown');append(block,append(el('div','row'),el('span','',human(component.name)+(component.informational?' · informational':'')),el('b','',number(component.points))));if(!component.informational&&component.points>0){const bar=el('div','bar'),fill=el('i');fill.style.width=Math.min(100,component.points/Math.max(1,s.score)*100)+'%';bar.append(fill);block.append(bar)}block.append(note(component.explanation));components.append(block)}
 if(s.exposure_limitations?.length)components.append(el('h3','','Exposure analysis limits'),list(s.exposure_limitations));components.append(note(`Analyzed nonblank lines: ${number(s.analyzed_lines)} · Issues / 1,000 lines: ${number(s.debt_density_per_kloc)}`));append(columns,scanners,components);view.append(columns);
 view.append(debtViews(d.debt_views,path=>showFileFindings(entry,path)));
 const triage=panel('AI triage');append(triage,badge(!d.triage_attempted?'not_requested':d.triage_complete?'success':'partial'),note(`${d.triage_results?.length||0} explanations · ${number(d.triage_provider_calls)} provider calls · ${number(d.triage_cache_hits)} cache hits`),formatErrors(d.triage_errors));view.append(triage);
 const findingPanel=panel();findingPanel.append(sectionHead('Prioritize the findings',button('View all findings →',()=>{location.hash='findings'})));const items=logicalFindings(d).slice(0,5);if(items.length)findingPanel.append(findingTable(items,entry));else findingPanel.append(note('No open findings were returned. Interpret this alongside scanner completeness.'));view.append(findingPanel);
 const scope=scopePanel(d,entry);if(scope)view.append(scope);
 const patterns=s.recurring_patterns||[];if(patterns.length){const p=panel('Recurring patterns');for(const pattern of patterns){append(p,append(el('div','pattern'),el('strong','',pattern.representative_message),note(`${pattern.file_count} files · ${pattern.occurrence_count} occurrences`),el('p','mono',(pattern.files||[]).join(' · '))))}view.append(p)}
}
function renderReadiness(view){const p=panel('Local tool availability');const tools=state.health?.backend?.scanners||{};for(const[name,available]of Object.entries(tools))append(p,append(el('div','scanner'),append(el('div','row'),el('strong','',name),badge(available?'available':name==='osv-scanner'?'skipped':'not_found'))));if(tools['osv-scanner']===false)p.append(note('osv-scanner is optional: not installed; dependency checks skipped.'));p.append(note('Availability checks whether executables can be found. A scan confirms whether they actually run successfully. Missing scanners produce an incomplete result.'));view.append(p)}
function logicalFindings(scan){const scored=scan.security_debt?.scored_findings;if(scored)return scored.map(scoredView).sort((a,b)=>(ranks[a.severity]??5)-(ranks[b.severity]??5)||(b._score||0)-(a._score||0));return(scan.findings||[]).filter(f=>f.status==='open').sort((a,b)=>(ranks[a.severity]??5)-(ranks[b.severity]??5))}
function findingTable(items,entry){const wrap=el('div','table-wrap'),table=el('table'),head=el('thead'),hr=el('tr');for(const name of ['Severity','Finding / source','Category','Points'])hr.append(el('th','',name));head.append(hr);const body=el('tbody');for(const f of items){const row=el('tr'),desc=el('td'),b=el('button','finding-button',f.message);b.type='button';b.addEventListener('click',()=>openFinding(f,entry));append(desc,b,...findingTags(f).map(tag=>el('span','badge',tag)),['security','secret'].includes(f.category)?exposureBadge(f):null,el('div','path',`${f.file_path}:${f.start_line}${f.end_line?'-'+f.end_line:''} · ${f.tool} / ${f.rule_id}`));const merged=mergeInfo(entry.data,f);if(merged)append(desc,el('span','badge',`Found by ${merged.count} rules/tools`),note(merged.reason));append(row,append(el('td'),badge(f.severity)),desc,el('td','',human(f.category)),el('td','mono',number(f._score)));body.append(row)}append(table,head,body);wrap.append(table);return wrap}
function renderFindings(view){const entry=current('scan');if(!entry){view.append(empty('Your findings will appear here.','Run a scan for this repository, or open a completed scan from this session.','⌕'),button('Go to scan setup',()=>location.hash='overview'));return}
 append(view,meta(entry),completeness(entry.data));const toolbar=el('div','toolbar'),search=el('input');search.type='search';search.placeholder='Search findings, paths, rules…';search.setAttribute('aria-label','Search findings');const severity=select('severity-filter','Severity',[['','All severities'],...Object.keys(ranks).map(v=>[v,human(v)])]).input;severity.setAttribute('aria-label','Filter by severity');const category=select('category-filter','Category',[['','All categories'],...['security','secret','architecture','maintainability'].map(v=>[v,human(v)])]).input;category.setAttribute('aria-label','Filter by category');append(toolbar,search,severity,category);view.append(toolbar);const results=el('div');view.append(results);const items=logicalFindings(entry.data);
 function filter(){const term=search.value.trim().toLowerCase();const matches=items.filter(f=>(!severity.value||f.severity===severity.value)&&(!category.value||f.category===category.value)&&[f.message,f.file_path,f.rule_id,f.tool,f.cwe_id].join(' ').toLowerCase().includes(term));results.replaceChildren(el('p','result-count',`${matches.length} of ${items.length} unique open findings`));results.append(matches.length?findingTable(matches,entry):empty('No matching findings.','Try another search or filter.'))}
 search.addEventListener('input',filter);severity.addEventListener('change',filter);category.addEventListener('change',filter);filter();
}
async function openFinding(f,entry){
 const sequence=++state.detailSequence,detail=$('finding-detail');detail.replaceChildren();append(detail,el('h2','',f.message),el('p','path',`${f.file_path}:${f.start_line} · ${f.tool} / ${f.rule_id}`));detail.querySelector('h2').id='finding-title';const grid=el('div','detail-grid');for(const[label,value]of [['Scanner severity',human(f.severity)],['Category',human(f.category)],['Score contribution',number(f._score)],['Remediation effort',human(f._effort)],['Confidence',f.confidence==null?'Not provided':number(f.confidence)],['CWE',f.cwe_id||'Not provided']])append(grid,append(el('div'),el('span','',label),el('b','',value)));detail.append(grid);if(f._explanation)detail.append(note(f._explanation));detail.append(exposurePanel(f,entry.data.security_debt?.exposure_limitations));
 const evidence=el('section','detail-section');append(evidence,el('h3','','Source context'),note(f._snapshot!=null?'Captured from the scanned source snapshot before it was deleted. Secret context is withheld.':'Read from the current local file. It may have changed since the scan; context is redacted and bounded.'));const code=el('pre','code','Loading source context…');code.tabIndex=0;code.setAttribute('aria-label','Redacted source code');evidence.append(code);detail.append(evidence);
 const group=entry.data.security_debt?.correlation_groups?.find(g=>g.representative.fingerprint===f.fingerprint);if(group&&group.findings.length>1){const p=el('section','detail-section');append(p,el('h3','',`${group.findings.length} scanner reports grouped together`),note(group.reason),list(group.findings.map(x=>`${x.tool} / ${x.rule_id} · ${x.file_path}:${x.start_line}`)));detail.append(p)}
 const triage=entry.data.triage_results?.find(t=>t.finding_id===f.finding_id)||entry.data.triage_results?.find(t=>t.fingerprint===f.fingerprint);const ai=el('section','detail-section');ai.append(el('h3','','AI assessment'));if(triage){ai.append(note(triageAttributionText(entry.data.triage_providers?.[f.fingerprint])))}
 if(triage)append(ai,note('AI-recommended priority: '+human(triage.priority)+' · Separate from scanner severity.'),el('p','',triage.summary),note(triage.rationale),el('h3','','Suggested steps'),list(triage.remediation_steps),el('h3','','Supporting evidence'),triage.evidence?.length?list(triage.evidence):note('No additional evidence returned.'),el('h3','','Limitations'),triage.limitations?.length?list(triage.limitations):note('No limitations were supplied by the provider.'),note('Human review is required.'));
 else ai.append(note(entry.data.triage_attempted?'No AI assessment was returned for this finding. See scan triage status.':'AI triage was not requested for this scan.'));detail.append(ai);
 if(f._snapshot!=null)append(detail,note('This snapshot was deleted after scanning. Native patch verification prepares the source again; AI fixes require a local checkout.'),button('Verify a source patch →',()=>{state.fixMode=entry.job.operation==='github'?'verify_github':'verify_upload';state.nativeVerifyUrl=entry.data.source?.url||'';$('finding-dialog').close();location.hash='fixes'}));
 if(f.category==='secret')detail.append(el('div','notice','Secret findings require credential rotation and appropriate cleanup. The backend refuses AI code fixes for these findings.'));
 else if(f._snapshot==null){const b=button('Review an AI fix →',()=>{state.selectedFingerprint=f.fingerprint;state.fixMode='ai';$('repo-path').value=entry.job.repo_path;$('finding-dialog').close();location.hash='fixes'});b.disabled=!!state.busy;detail.append(b)}
 $('finding-dialog').showModal();
 if(f._snapshot!=null){code.textContent=f._snapshot;return}
 try{const response=await api.context(entry.job.id,f.fingerprint);if(sequence===state.detailSequence)code.textContent=response.context||'Source context unavailable.'}catch(error){if(sequence===state.detailSequence)code.textContent='Source context unavailable: '+error.message}
}

function renderFixes(view){
 if(state.fixMode.startsWith('verify_')){renderNativeVerify(view);return}
 const tabs=el('div','split-tabs');for(const[key,title]of [['ai','AI fix proposal'],['patch','Verify a patch'],['verify_github','GitHub patch'],['verify_upload','Upload patch']]){const b=button(title,()=>{state.fixMode=key;render()},'');b.className='';b.setAttribute('aria-pressed',String(state.fixMode===key));tabs.append(b)}view.append(tabs);
 const p=panel(state.fixMode==='ai'?'Propose and verify a change':'Check a patch before applying it');
 if(state.fixMode==='ai'){
  const entry=current('scan');const options=[['','Top security finding (backend selection)'],...(entry?logicalFindings(entry.data).filter(f=>f.category!=='secret').map(f=>[f.fingerprint,`${f.file_path}:${f.start_line} · ${f.rule_id}`]):[])];const picker=select('fix-finding','Finding to investigate',options);if(options.some(([value])=>value===state.selectedFingerprint))picker.input.value=state.selectedFingerprint;p.append(picker.wrapper);
  p.append(note('The backend uses the provider order below to propose a patch, then checks it in a separate copy. Cloud calls may consume API quota. The original repository is not changed.'));
  p.append(aiNotice(state.health?.backend));
  p.append(check('fix-tests','Run repository tests','Executes the repository’s own code in the temporary copy, as your current user. Use only with a project you trust.').wrapper);
  const b=operationButton('Request AI fix & verify',()=>{try{execute('fix',{repo_path:repo(),fingerprint:$('fix-finding').value,run_tests:checked('fix-tests'),timeout:180})}catch(e){notice(e.message,'error')}},'fix');if(!state.health?.backend?.ai_configured)b.disabled=true;p.append(b);
 }else{
  const f=el('div','field'),label=el('label','','Patch file (.diff or .patch)'),input=el('input');label.htmlFor='patch-file';input.id='patch-file';input.type='file';input.accept='.diff,.patch,text/plain';append(f,label,input);p.append(f);
  const textLabel=el('label','mini-label','Or paste a unified diff');textLabel.htmlFor='patch-text';const area=el('textarea');area.id='patch-text';area.spellcheck=false;area.placeholder='diff --git a/file.py b/file.py\n…';append(p,textLabel,area);
  input.addEventListener('change',async()=>{const file=input.files[0];if(!file)return;if(file.size>200000){notice('Choose a patch smaller than 200 KB.','error');input.value='';return}try{const bytes=new Uint8Array(await file.arrayBuffer());const encoding=bytes[0]===255&&bytes[1]===254?'utf-16le':bytes[0]===254&&bytes[1]===255?'utf-16be':'utf-8';area.value=new TextDecoder(encoding,{fatal:true}).decode(bytes);notice('')}catch{notice('The patch could not be decoded as text.','error')}});
  append(p,check('verify-tests','Run repository tests','Executes repository code in the temporary copy as your current user. Off by default.').wrapper,check('verify-strict','Treat every new finding as a regression','Default behavior flags new findings at medium severity or above.').wrapper);
  p.append(operationButton('Verify patch ↗',()=>{try{if(!area.value.trim())throw new Error('Choose or paste a patch first.');execute('verify',{repo_path:repo(),patch:area.value,run_tests:checked('verify-tests'),strict:checked('verify-strict'),timeout:180})}catch(e){notice(e.message,'error')}},'verify'));
  p.append(note('The backend validates the patch, scans a temporary copy before and after applying it, and reports what changed.'));
 }
 view.append(p);const entry=current(state.fixMode==='ai'?'fix':'verify');if(!entry){view.append(empty('A proposal needs a review.','Completed results show what resolved, what remains, what appeared, and which checks actually ran.','⌘'));return}
 view.append(meta(entry));const report=entry.job.operation==='fix'?entry.data.verification:entry.data;
 if(entry.job.operation==='fix'){
  const proposal=panel('AI proposal');append(proposal,badge(entry.data.status),formatErrors(entry.data.errors));if(entry.data.proposal){append(proposal,note(`Provider: ${entry.data.proposal.provider}`),el('p','',entry.data.proposal.explanation),diff(entry.data.proposal.diff_text),button('Download proposed patch',()=>saveFile(entry.data.proposal.diff_text,'silentsec-proposed-fix.diff','text/plain')))}append(proposal,formatErrors(entry.data.limitations));view.append(proposal);
 }
 if(report)view.append(verification(report));
}
function diff(value){const pre=el('pre','code');pre.tabIndex=0;pre.setAttribute('aria-label','Proposed patch');for(const line of String(value||'No patch returned.').split('\n'))pre.append(el('span','diff-line '+(line.startsWith('@@')||line.startsWith('diff ')?'diff-header':line.startsWith('+')?'diff-add':line.startsWith('-')?'diff-remove':''),line||' '));return pre}
function summaries(title,items){const section=el('div','detail-section');section.append(el('h3','',title));section.append(items?.length?list(items.map(f=>`${f.file_path}:${f.start_line} · ${f.rule_id} · ${human(f.severity)}`)):note('None reported.'));return section}
function verification(report){const p=panel();append(p,append(el('div','verdict'),el('h2','','Verification result'),badge(report.verdict)),formatErrors(report.reasons));const counts=el('div','checks-grid');for(const[key,title]of [['resolved','Resolved'],['remaining','Remaining'],['new','New findings']])append(counts,append(el('div'),el('strong','',report[key]?.length||0),el('span','',title)));p.append(counts);p.append(note(`Debt score: ${number(report.score_before)} → ${number(report.score_after)} · Uncapped: ${number(report.raw_score_before)} → ${number(report.raw_score_after)}`));
 const checks=el('section','detail-section');append(checks,el('h3','','Checks actually run'),list(report.checks_run));if(report.tests){append(checks,badge(report.tests.timed_out?'not_verified':report.tests.passed?'success':'failed'),note(`Tests: ${report.tests.timed_out?'timed out':report.tests.passed?'passed':'failed'} · Exit code: ${text(report.tests.exit_code)}`));if(report.tests.output_tail){const pre=el('pre','code',report.tests.output_tail);pre.tabIndex=0;checks.append(pre)}}else checks.append(el('div','notice','Repository tests were not run. A verified-fix verdict may be based on scanner results alone.'));p.append(checks);
 append(p,summaries('Resolved findings',report.resolved),summaries('Remaining findings',report.remaining),summaries('New findings',report.new));const scanner=el('section','detail-section');scanner.append(el('h3','','Scanner status before → after'));for(const name of new Set([...Object.keys(report.scanners_before||{}),...Object.keys(report.scanners_after||{})]))scanner.append(note(`${name}: ${human(report.scanners_before?.[name])} → ${human(report.scanners_after?.[name])}`));p.append(scanner);
 if(report.diff_text){const d=el('details');append(d,el('summary','','Inspect verified patch'),diff(report.diff_text),button('Download patch',()=>saveFile(report.diff_text,'silentsec-verified-patch.diff','text/plain')));p.append(d)}append(p,el('h3','detail-section','Limits of verification'),list(report.limitations));return p;
}

function renderHistory(view){const p=panel('Read the repository’s history');const grid=el('div','form-grid');append(grid,field('history-commits','Recent commits','number',10,1,50).wrapper,field('history-timeout','Per-scanner timeout (seconds)').wrapper);append(p,note('Scans committed files along the current branch’s first-parent history. A downloaded ZIP has no Git history.'),grid,check('history-cache','Reuse stored commit scans','',true).wrapper,operationButton('Build Time Machine ↗',()=>{try{execute('history',{repo_path:repo(),commits:numeric('history-commits',10),timeout:numeric('history-timeout',180),use_cache:checked('history-cache')})}catch(e){notice(e.message,'error')}},'history'));view.append(p);const entry=current('history');if(!entry){view.append(empty('Changes need a timeline.','Choose a local Git checkout and build its history. The first commit in the selected range becomes the baseline.','↗'));return}append(view,meta(entry));const d=entry.data;const summary=panel('Debt across commits');append(summary,note(`Branch: ${d.branch} · ${d.points.length} commits · Analysis version: ${d.analysis_version}`));if(d.shallow_clone)summary.append(el('div','notice','This is a shallow clone. Older commits may be missing.'));summary.append(note(`${returnedCount(d.points)} issue(s) came back after being fixed`),chart(d.points));summary.append(note('Uncapped debt score. Lines are interrupted at incomplete scans; a missing check is not a confirmed improvement.'));view.append(summary);
 const wrap=el('div','table-wrap'),table=el('table'),head=el('tr');for(const title of ['Commit','Change','Uncapped debt','Introduced','Fixed','Attribution'])head.append(el('th','',title));const thead=el('thead');thead.append(head);table.append(thead);const tbody=el('tbody'),detail=el('section','commit-detail');detail.hidden=true;
 for(const point of d.points){const row=el('tr'),cell=el('td'),b=el('button','commit-button',point.short_sha);b.type='button';b.addEventListener('click',()=>{detail.hidden=false;detail.replaceChildren(...[el('h3','',`${point.short_sha} · ${point.subject}`),cameBack(point),note(`${point.committed_at} · ${point.from_cache?'Cached scan':'Fresh scan'}`),badge(point.attribution),formatErrors(point.scanner_problems),summaries('Introduced findings',point.introduced),summaries('Fixed findings',point.fixed)].filter(Boolean));detail.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'nearest'})});cell.append(b);append(row,cell,append(el('td'),cameBack(point),el('span','',point.subject)),el('td','mono',number(point.raw_score)),el('td','mono',point.attribution==='known'?point.introduced.length:'—'),el('td','mono',point.attribution==='known'?point.fixed.length:'—'),append(el('td'),badge(point.attribution)));tbody.append(row)}table.append(tbody);wrap.append(table);append(view,detail,wrap,list(d.limitations));
}
function chart(points){const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.classList.add('chart');svg.setAttribute('viewBox','0 0 800 200');svg.setAttribute('role','img');svg.setAttribute('aria-label','Uncapped security debt by commit. Full values are in the following table.');if(!points.length)return svg;const max=Math.max(1,...points.map(p=>p.raw_score));const x=i=>30+i*740/Math.max(1,points.length-1),y=p=>170-p.raw_score/max*140;const base=document.createElementNS(ns,'line');for(const[k,v]of Object.entries({x1:30,y1:170,x2:770,y2:170,stroke:'#b8a0ff30'}))base.setAttribute(k,v);svg.append(base);points.forEach((p,i)=>{if(i&&p.complete&&points[i-1].complete){const line=document.createElementNS(ns,'line');for(const[k,v]of Object.entries({x1:x(i-1),y1:y(points[i-1]),x2:x(i),y2:y(p),stroke:'#b8a0ff','stroke-width':2}))line.setAttribute(k,v);svg.append(line)}const dot=document.createElementNS(ns,'circle');for(const[k,v]of Object.entries({cx:x(i),cy:y(p),r:4,fill:p.complete?'#8be2e8':'#ecc58c'}))dot.setAttribute(k,v);const title=document.createElementNS(ns,'title');title.textContent=`${p.short_sha}: ${p.raw_score}${p.complete?'':' (incomplete)'}`;dot.append(title);svg.append(dot);if(reintroducedChanges(p).length){const ring=document.createElementNS(ns,'circle');for(const[k,v]of Object.entries({cx:x(i),cy:y(p),r:9,fill:'none',stroke:'#f2aa58','stroke-width':2}))ring.setAttribute(k,v);svg.append(ring)}});return svg}

function renderReports(view){const p=panel('Generate a reviewable report');p.append(note('Runs a fresh scan and writes the backend’s offline HTML report. Download it after generation.'));const include=check('report-history','Include Git history','Requires a Git checkout; scans recent commits.');p.append(include.wrapper);const grid=el('div','form-grid');append(grid,field('report-commits','Recent commits','number',10,1,50).wrapper,field('report-timeout','Per-scanner timeout (seconds)').wrapper);p.append(grid);const ai=check('report-ai','Include AI triage','Uses the configured provider order below. Cloud calls may consume API quota.');ai.input.disabled=!state.health?.backend?.ai_configured;p.append(ai.wrapper,aiNotice(state.health?.backend));
 const fixes=state.jobs.filter(j=>['fix','verify'].includes(j.operation)&&j.status==='succeeded'&&sameRepo(j.repo_path));if(fixes.length){p.append(el('h3','detail-section','Include completed fix reports'));const select=el('div','report-selection');for(const job of fixes){const c=check('report-fix-'+job.id,`${human(job.operation)} · ${new Date(job.started_at*1000).toLocaleTimeString()}`);c.input.value=job.id;c.input.dataset.fixReport='';select.append(c.wrapper)}p.append(select)}
 p.append(operationButton('Generate HTML report ↗',()=>{try{execute('report',{repo_path:repo(),include_history:checked('report-history'),commits:numeric('report-commits',10),timeout:numeric('report-timeout',180),ai_triage:checked('report-ai'),fix_job_ids:[...document.querySelectorAll('[data-fix-report]:checked')].map(x=>x.value)})}catch(e){notice(e.message,'error')}},'report'));view.append(p);const entry=current('report');if(!entry){view.append(empty('Evidence you can take with you.','Generate a report to review findings, score components, and optional history and fix results.','▤'));return}view.append(meta(entry));const result=panel('Report ready');append(result,completeness(entry.data.scan),note(`Scan status: ${human(entry.data.scan.status)} · Score: ${number(entry.data.scan.security_debt?.score)} / 100`),button('Download HTML report ↓',async()=>{try{saveFile(await api.report(entry.job.id),'silentsec-report.html')}catch(e){notice(e.message,'error')}},''),note('The downloaded report opens locally in your browser and does not require this server.'));view.append(result)}

function render(){
 const requested=location.hash.slice(1);state.view=titles[requested]?requested:'overview';const[title,description]=titles[state.view];document.querySelector('.project-bar').hidden=state.view==='sources'||(state.view==='fixes'&&state.fixMode.startsWith('verify_'));$('view-title').textContent=title;$('view-description').textContent=description;$('breadcrumb').textContent=labels[state.view];document.title=`SilentSec — ${labels[state.view]}`;
 document.querySelectorAll('[data-view]').forEach(a=>{if(a.dataset.view===state.view)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});const view=$('view');view.replaceChildren();({overview:renderOverview,findings:renderFindings,fixes:renderFixes,history:renderHistory,reports:renderReports,sources:renderSources,gate:renderGate})[state.view](view);updateButtons();if(state.view==='fixes'&&!state.health?.backend?.ai_configured){const b=view.querySelector('[data-operation=fix]');if(b)b.disabled=true}
}
$('repo-path').addEventListener('change',()=>{notice('');render()});
$('recent-jobs').addEventListener('change',()=>{const job=state.jobs.find(j=>j.id===$('recent-jobs').value);if(job)load(job)});
$('close-finding').addEventListener('click',()=>$('finding-dialog').close());
$('finding-dialog').addEventListener('close',()=>{state.detailSequence++});
window.addEventListener('hashchange',()=>{notice('');render()});
async function boot(){
 render();try{state.health=await api.connect();if(state.health.backend)$('backend-version').textContent=`SilentSec ${state.health.backend.version} · backend commit ${state.health.backend.commit||'unavailable (archive)'}${state.health.backend.archive_revision?' · archive '+state.health.backend.archive_revision:''}`;$('connection').textContent=state.health.backend_ready?`LOCAL · API v${state.health.api_version}`:'LOCAL · SETUP NEEDED';if(!state.health.backend_ready){const n=$('setup-notice');n.hidden=false;n.className='notice error';n.textContent=state.health.error||'Run setup.ps1 to install backend dependencies, then restart.'}await refreshJobs();render();const active=state.jobs.find(j=>['queued','running'].includes(j.status));if(active){state.busy=active;updateButtons();status('Reconnected to the running operation.');poll(active.id).catch(e=>{state.busy=null;status('');notice(e.message,'error');updateButtons()})}}catch(error){$('connection').textContent='LOCAL SERVICE UNAVAILABLE';notice('Start the workspace with Start-SilentSec.cmd, then refresh this page. '+error.message,'error')}
}
boot();

function renderSources(view){
 const columns=el('div','columns'),github=panel('Public GitHub repository'),upload=panel('ZIP or source file');
 const url=field('github-url','Public repository URL','url','');url.input.placeholder='https://github.com/owner/repository';
 const commits=field('github-commits','History commits (0 turns history off)','number',0,0,20);
 append(github,url.wrapper,commits.wrapper,note('Downloads a public repository from GitHub over the internet. Scanning runs locally. Private repositories are not supported.'),operationButton('Scan GitHub repository',()=>{execute('github',{url:url.input.value.trim(),commits:Number(commits.input.value),timeout:180})},'github'));
 const label=el('label','mini-label','Choose one file, up to 20 MB');label.htmlFor='source-upload';const file=el('input');file.type='file';file.id='source-upload';file.style.width='100%';
 append(upload,label,file,note('A ZIP archive or single source file is sent only to this local server. Uploads have no Git history. AI is off for these native API scans.'),operationButton('Scan selected file',async()=>{
  const selected=file.files[0];if(!selected){notice('Choose a ZIP or source file first.','error');return}if(!selected.size||selected.size>20*1024*1024){notice('Choose a nonempty file up to 20 MB.','error');return}
  const bytes=new Uint8Array(await selected.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));
  execute('upload',{filename:selected.name,content:btoa(binary)});
 },'upload'));append(columns,github,upload);view.append(columns);
 const entries=['github','upload'].map(key=>state.results[key]).filter(Boolean).sort((a,b)=>b.job.started_at-a.job.started_at),entry=entries[0];
 if(!entry){view.append(empty('From source to evidence.','Choose a public repository or a local file. The results use the newer backend’s native scan response.'));return}
 const data=entry.data,summary=data.summary;view.append(meta(entry));
 if(!summary){view.append(el('div','notice error','The backend did not return a score summary.'));return}
 if(!summary.complete)view.append(el('div','notice','Incomplete scan: one or more scanners did not complete successfully. Review coverage below.'));
 const stats=el('div','stats');append(stats,stat('Security debt',number(summary.score),`Uncapped: ${number(summary.raw_score)}`,'/100'),stat('Security risk',human(summary.security_risk),`${number(summary.security_points)} security points`),stat('Architecture risk',human(summary.architecture_risk),`${number(summary.architecture_points)} architecture points`),stat('Unique issues',number(summary.unique_issues),`${number(summary.duplicates_merged)} duplicates merged`));view.append(stats);
 const coverage=panel('Scanner coverage');for(const scanner of data.scanners||[])append(coverage,append(el('div','scanner'),append(el('div','row'),el('strong','',scanner.name),badge(scanner.status)),note(`${scanner.findings} findings · ${number(scanner.duration_seconds)}s`),formatErrors(scanner.errors)));view.append(coverage);
 view.append(debtViews(data.debt_views,path=>showFileFindings(entry,path)));
 const items=(data.issues||[]).map(nativeIssueView);
 const findings=panel('Source findings'),search=el('input');search.type='search';search.placeholder='Search findings and source paths';search.setAttribute('aria-label','Search source findings');search.style.width='100%';const results=el('div');append(findings,search,results);function filter(){const matched=items.filter(f=>(f.message+' '+f.file_path+' '+f.rule_id).toLowerCase().includes(search.value.toLowerCase()));results.replaceChildren(el('p','result-count',`${matched.length} findings`),matched.length?findingTable(matched,entry):note('No matching findings.'))}search.addEventListener('input',filter);filter();view.append(findings);
 const history=panel('Commit history');if(data.timeline){append(history,note(`${returnedCount(data.timeline.points)} issue(s) came back after being fixed`),chart(data.timeline.points));const table=el('table'),head=el('tr');for(const value of ['Commit','Change','Uncapped score','Attribution'])head.append(el('th','',value));table.append(head);for(const point of data.timeline.points)append(table,append(el('tr'),el('td','mono',point.short_sha),append(el('td'),cameBack(point),el('span','',point.subject)),el('td','mono',number(point.raw_score)),append(el('td'),badge(point.attribution))));const wrap=el('div','table-wrap');wrap.append(table);history.append(wrap)}else history.append(note(data.timeline_note||'History was not included.'));view.append(history);
 const report=panel('Offline report');append(report,note('This report was captured by the native API while the source snapshot still existed.'),button('Download HTML report',async()=>{try{saveFile(await api.report(entry.job.id),'silentsec-report.html')}catch(error){notice(error.message,'error')}},''));view.append(report);
}

function cameBack(point){
 const items=reintroducedChanges(point);if(!items.length)return null;
 const block=el('div','came-back');for(const f of items)block.append(el('div','',`Came back: ${f.tool} ${f.rule_id} at ${f.file_path}:${f.start_line} (fixed in ${f.previously_fixed_in||'unknown'})`));return block;
}
function gateTable(title,items){const p=panel(title);if(!items?.length){p.append(note('None reported.'));return p}const wrap=el('div','table-wrap'),table=el('table'),head=el('tr');for(const label of ['Severity','Finding','Source'])head.append(el('th','',label));table.append(head);for(const f of items)table.append(append(el('tr'),append(el('td'),badge(f.severity)),el('td','',f.message),el('td','path',`${f.tool} ${f.rule_id} · ${f.file_path}:${f.start_line}`)));wrap.append(table);p.append(wrap);return p}
function renderGate(view){
 const p=panel('PR security gate'),grid=el('div','form-grid');append(grid,field('gate-base','Base revision','text','main').wrapper,field('gate-head','Head revision','text','HEAD').wrapper,select('gate-severity','Block new security findings at or above',Object.keys(ranks).map(x=>[x,human(x)])).wrapper);grid.querySelector('#gate-severity').value='high';append(p,note('Existing issues do not block. Only newly introduced issues are checked against this policy.'),grid,check('gate-architecture','Also block new architecture/maintainability findings').wrapper,check('gate-tests','Also block new findings in test and sample code').wrapper,operationButton('Run PR check',()=>{try{execute('gate',{repo_path:repo(),base:$('gate-base').value,head:$('gate-head').value,fail_on:$('gate-severity').value,fail_on_architecture:checked('gate-architecture'),include_tests:checked('gate-tests'),timeout:180})}catch(e){notice(e.message,'error')}},'gate'));view.append(p);
 const entry=current('gate');if(!entry)return;const d=entry.data;$('gate-base').value=d.base_ref;$('gate-head').value=d.head_ref;$('gate-severity').value=d.policy.fail_on;$('gate-architecture').checked=d.policy.fail_on_architecture;$('gate-tests').checked=!!d.policy.include_tests;view.append(meta(entry));const verdict=panel();append(verdict,append(el('div','verdict gate-verdict '+d.verdict),el('h2','',d.verdict==='incomplete'?'Cannot decide':d.verdict==='pass'?'Change passes':'Change blocked'),badge(d.verdict)),list(d.reasons),note(`Uncapped debt: ${number(d.score_before)} → ${number(d.score_after)}`),note(`${d.blocking_issues} blocking issues · ${d.new_issues} new issues · ${d.existing_issues} existing issues`),note(`Compared ${d.base_ref} (${d.base_sha}) → ${d.head_ref} (${d.head_sha})`),formatErrors(d.scanner_problems));view.append(verdict,gateTable('Blocking findings',d.blocking),gateTable('Warnings',d.warnings),gateTable('Other new findings',d.other_new),gateTable('Resolved findings',d.resolved),list(d.limitations));
}
function renderNativeVerify(view){
 const tabs=el('div','split-tabs');for(const[key,label]of [['ai','Local AI fix'],['patch','Local patch'],['verify_github','GitHub patch'],['verify_upload','Upload patch']]){const b=button(label,()=>{state.fixMode=key;render()},'quiet');b.setAttribute('aria-pressed',String(key===state.fixMode));tabs.append(b)}view.append(tabs);
 const mode=state.fixMode,p=panel(mode==='verify_github'?'Verify a GitHub patch':'Verify an uploaded source patch');p.append(note('Repository tests are never run by these native verification endpoints. Source is prepared again; nothing is applied to the original repository.'));
 let source;
 if(mode==='verify_github'){source=field('verify-url','Public GitHub repository URL','url',state.nativeVerifyUrl||'');p.append(source.wrapper);p.append(field('verify-targets','Optional target fingerprints (one per line)','text','').wrapper)}else{const label=el('label','mini-label','Reattach the original ZIP or source file (up to 20 MB)');label.htmlFor='verify-source';source={input:el('input')};source.input.type='file';source.input.id='verify-source';append(p,label,source.input)}
 const label=el('label','mini-label','Unified patch'),area=el('textarea');label.htmlFor='native-patch';area.id='native-patch';area.spellcheck=false;const fileLabel=el('label','mini-label','Or load a UTF-8/UTF-16 patch file (up to 1 MB)'),patchFile=el('input');patchFile.type='file';patchFile.id='native-patch-file';patchFile.accept='.diff,.patch,text/plain';fileLabel.htmlFor=patchFile.id;patchFile.addEventListener('change',async()=>{try{const file=patchFile.files[0];if(!file)return;if(file.size>1000000)throw new Error('Patch exceeds 1 MB.');const bytes=new Uint8Array(await file.arrayBuffer());area.value=new TextDecoder(bytes[0]===255&&bytes[1]===254?'utf-16le':bytes[0]===254&&bytes[1]===255?'utf-16be':'utf-8',{fatal:true}).decode(bytes)}catch(e){notice(e.message,'error')}});append(p,fileLabel,patchFile,label,area,operationButton('Verify source patch',async()=>{
  try{if(!area.value.trim())throw new Error('Paste or load a patch first.');let args={patch:area.value};if(mode==='verify_github'){args.url=source.input.value.trim();const targets=$('verify-targets').value.split(/\s+/).filter(Boolean);if(targets.length)args.targets=targets}else{const file=source.input.files[0];if(!file||!file.size||file.size>20*1024*1024)throw new Error('Choose a nonempty source file up to 20 MB.');const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));args={...args,filename:file.name,content:btoa(binary)}}execute(mode,args)}catch(e){notice(e.message,'error')}
 },mode));view.append(p);const entry=state.results[mode];if(entry){view.append(meta(entry),verification(entry.data))}
}

function exposureBadge(finding){
 const exposure=exposureOf(finding);
 const labels={reachable:'Reachable in code',not_reachable:'No detected entry-point path',unknown:'Exposure unknown'};
 return el('span','badge exposure-'+exposure.state,labels[exposure.state]);
}
function exposurePanel(finding,limitations){
 const exposure=exposureOf(finding),panel=el('section','detail-section');
 append(panel,el('h3','','Entry-point exposure'),exposureBadge(finding));
 if(exposure.path.length)append(panel,el('h3','','Detected call path'),list(exposure.path));
 else panel.append(note(exposure.state==='not_reachable'?'The analysis did not find a path from a detected entry point. Dynamic calls may be missed; this does not establish safety.':'No call path was supplied by the backend.'));
 if(exposure.factor!=null)panel.append(note('Backend exposure multiplier: ×'+number(exposure.factor)+'. Included in the returned score; the frontend does not recalculate it.'));
 panel.append(note('A call path in source code does not prove exploitability.'));
 if(limitations?.length)panel.append(list(limitations));
 return panel;
}

function showFileFindings(entry,path){
 const detail=$('finding-detail');detail.replaceChildren(el('h2','',path));detail.querySelector('h2').id='finding-title';
 const items=entry.data.issues?entry.data.issues.map(nativeIssueView):logicalFindings(entry.data);
 detail.append(findingTable(items.filter(f=>f.file_path.replaceAll('\\','/')===path.replaceAll('\\','/')),entry));
 $('finding-dialog').showModal();
function scopePanel(d,entry){
 const lines=scopeLines(d.scope);if(!lines.length)return null;
 const p=panel('Not in the score');for(const line of lines)p.append(note(line));
 if(d.scope?.ignored_files?.length){const files=el('details');files.append(el('summary','','Files excluded by .silentsecignore'),list(d.scope.ignored_files));p.append(files)}
 const debt=d.test_code_debt;if(debt?.scored_findings?.length){const box=el('details');box.append(el('summary','',`Test and sample code: ${debt.unique_open_findings_count} issue(s), ${number(debt.raw_score)} points (not in the score)`),note('Test and sample code often contains deliberate examples of bad code. Review these, but they do not change the score.'),findingTable(debt.scored_findings.map(scoredView),entry));p.append(box)}
 return p;
}
