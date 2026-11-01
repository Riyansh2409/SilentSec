const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.events={};this.style={};this.attributes={};this.value='';this.textContent=''}
 append(...nodes){for(const n of nodes){this.children.push(n);if(this.tag==='select'&&!this.value)this.value=n.value}}
 setAttribute(k,v){this.attributes[k]=v}
 addEventListener(k,f){this.events[k]=f}
 replaceChildren(...nodes){this.children=[];this.append(...nodes)}
 set innerHTML(_){throw Error('Unsafe HTML rendering')}
}
const document={createElement:t=>new Element(t),createElementNS:(_,t)=>new Element(t)};
const source=fs.readFileSync('web/debt-views.js','utf8').replace('export function','function');
const ctx={document};vm.createContext(ctx);vm.runInContext(source+';this.render=debtViews;',ctx);
const walk=n=>[n,...n.children.flatMap(walk)];
const data={files:[{path:'<img onerror=x>.py',points:15,issues:1,severity:'high'}],folders:[],nodes:[{id:'api',points:15,severity:'high'},{id:'db',points:0,severity:'none'}],edges:[{source:'api',target:'db'}],note:'Static imports only',omitted_nodes:0,omitted_edges:0,skipped_python_files:0};
let selected;
const view=ctx.render(data,p=>selected=p);
walk(view).find(n=>n.className==='debt-file').events.click();assert.equal(selected,'<img onerror=x>.py');
assert(walk(view).some(n=>n.textContent==='<img onerror=x>.py'));
const select=walk(view).find(n=>n.tag==='select');select.value='db';select.events.change();
assert(walk(view).some(n=>n.attributes['aria-label']==='Local imports into and out of db'));
assert(walk(view).some(n=>n.textContent==='Incoming imports (1)'));
walk(view).find(n=>n.attributes['aria-label']==='Inspect api').events.click();assert.equal(select.value,'api');
assert(walk(ctx.render({...data,files:[],nodes:[],edges:[]},()=>{})).some(n=>n.textContent==='No local Python import relationships detected.'));
assert(walk(ctx.render(null,()=>{})).some(n=>n.textContent.includes('older scan')));
