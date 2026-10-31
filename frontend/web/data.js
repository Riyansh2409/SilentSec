// Pure result interpretation, shared by the views and contract tests.
export const scanIncomplete = data => !data.security_debt_complete;
export const reintroducedChanges = point => (point.introduced || []).filter(item => item.reintroduced === true);
export const returnedCount = points => (points || []).reduce((count, point) => count + reintroducedChanges(point).length, 0);
export const findingTags = finding => [
  ...(finding.tool === 'osv-scanner' ? ['Dependency'] : []),
  ...(finding.rule_id === 'SSEC-ARCH-006' ? ['Hard to maintain'] : [])
];
export function mergeInfo(scan, finding) {
  const group = scan.security_debt?.correlation_groups?.find(g => g.representative.fingerprint === finding.fingerprint);
  return group?.findings?.length > 1 ? {count: group.findings.length, reason: group.reason} : null;
}

export function exposureOf(finding) {
  const known=['reachable','not_reachable','unknown'];
  return {state:known.includes(finding.exposure)?finding.exposure:'unknown',
    path:Array.isArray(finding.exposure_path)?finding.exposure_path:[],
    factor:typeof finding.exposure_factor==='number'?finding.exposure_factor:null};
}
export function aiDisclosure(config) {
  if(config?.ai_configuration_error)return 'AI configuration error: '+config.ai_configuration_error;
  const providers=config?.ai_providers||[];
  if(!providers.length)return 'AI is not configured. Set SILENTSEC_AI_PROVIDERS=ollama for local AI, or configure a cloud provider, then restart.';
  const chain=providers.map(p=>p.name+' / '+p.model+' ('+p.scope+')').join(' → ');
  return 'Configured order: '+chain+'. '+(config.ai_local_only?'Only local providers are configured.':'This chain includes external providers: sanitized source context may leave this computer, including on fallback.')+' Availability is checked when used.';
}

export function scoredView(item) {
 return {...item.finding,_score:item.score,_explanation:item.explanation,_effort:item.remediation_effort,
  exposure:item.exposure,exposure_path:item.exposure_path,exposure_factor:item.exposure_factor};
}
export function nativeIssueView(issue) {
 return {fingerprint:issue.fingerprint,finding_id:issue.fingerprint,severity:issue.severity,
  category:issue.category,message:issue.title,file_path:issue.file_path,start_line:issue.start_line,
  end_line:issue.end_line,cwe_id:issue.cwe_id,
  tool:(issue.sources||[]).map(s=>s.tool).join(', '),rule_id:(issue.sources||[]).map(s=>s.rule_id).join(', '),
  _score:issue.points,_effort:issue.fix_effort,_explanation:issue.score_explanation,
  _snapshot:issue.code||'Source context was not returned.',exposure:issue.exposure,exposure_path:issue.exposure_path};
}


export function triageAttributionText(value) {
  if(typeof value==='string' && value.trim())return 'Answered by: '+value;
  if(!value || typeof value!=='object')return 'Provider identity was not recorded for this result.';
  if(!value.provider)return value.cached?'Cached result; provider and model are unknown (older cache entry).':'Provider identity was not recorded for this result.';
  const name=value.provider+(value.model?' / '+value.model:' / model unknown');
  const locality=value.local===true?'local':value.local===false?'external':'locality unknown';
  return 'Answered by: '+name+' · '+locality+' · '+(value.cached?'cached result':'fresh result');
}
