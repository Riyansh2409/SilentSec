// Render repository text through textContent only; no remote graph libraries.
export function debtViews(data, onFile) {
 const make=(tag,text,cls)=>{const n=document.createElement(tag);if(text!=null)n.textContent=text;if(cls)n.className=cls;return n};
 const box=make('section',null,'panel debt-views');box.append(make('h2','Debt and dependencies'));
 if(!data){box.append(make('p','Visualization data is unavailable for this older scan. Run a new scan.'));return box}
 box.append(make('p',data.note,'note'));
 const colours={critical:'#ff7298',high:'#ff9cb8',medium:'#ecc58c',low:'#8be2e8',info:'#b8a0ff',none:'#aaa5bd'};
 const top=make('div');top.append(make('h3','Top 10 files by debt'));
 const max=Math.max(1,...data.files.map(r=>r.points));
 for(const r of data.files.slice(0,10)){
  const row=make('button',null,'debt-file');row.type='button';
  row.append(make('span',r.path,'path'),make('span',`${r.points} pts · ${r.issues} issues · ${r.severity}`));
  const track=make('span',null,'debt-track'),bar=make('span',null,'debt-fill');bar.style.width=`${r.points/max*100}%`;bar.style.background=colours[r.severity];track.append(bar);row.append(track);
  row.addEventListener('click',()=>onFile(r.path));top.append(row);
 }
 if(!data.files.length)top.append(make('p','No scored open findings. Check scanner completeness.'));
 box.append(top,make('h3','Folder debt map'));
 const folders=make('div',null,'debt-folders');
 for(const r of data.folders.slice(0,30)){
  const card=make('details',null,'debt-folder');card.style.borderColor=colours[r.severity];
  card.append(make('summary',`${r.path} · ${r.points} pts`),make('p',`${r.issues} issues · ${r.files} affected files · ${r.severity}`));
  for(const f of data.files.filter(f=>f.path.replaceAll('\\','/').split('/').slice(0,-1).join('/')=== (r.path==='.'?'':r.path))){const b=make('button',`${f.path} · ${f.points} pts`,'finding-button');b.type='button';b.addEventListener('click',()=>onFile(f.path));card.append(b)}folders.append(card);
 }
 box.append(folders);if(data.folders.length>30)box.append(make('p',`${data.folders.length-30} additional folders in JSON output.`));
 box.append(make('h3','Python dependency graph'),make('p','Select a module to inspect its incoming and outgoing imports. Node colours show highest finding severity.','note'));
 const label=make('label','Selected module '),select=make('select');label.append(select);box.append(label);
 for(const n of data.nodes){const o=make('option',`${n.id} · ${n.points} pts`);o.value=n.id;select.append(o)}
 const graph=make('div',null,'dependency-canvas'),detail=make('div');box.append(graph,detail);
 const svgNode=(tag,attrs,text)=>{const n=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const[k,v]of Object.entries(attrs))n.setAttribute(k,v);if(text!=null)n.textContent=text;return n};
 function draw(){
  graph.replaceChildren();detail.replaceChildren();const selected=select.value;
  const incoming=data.edges.filter(e=>e.target===selected).map(e=>e.source),outgoing=data.edges.filter(e=>e.source===selected).map(e=>e.target);
  if(!selected){graph.append(make('p','No local Python import relationships detected.'));select.disabled=true;return}
  const height=Math.max(180,Math.max(Math.min(10,incoming.length),Math.min(10,outgoing.length))*65+50),mid=height/2;
  const svg=svgNode('svg',{viewBox:`0 0 1000 ${height}`,role:'img','aria-label':`Local imports into and out of ${selected}`});
  const defs=svgNode('defs',{}),marker=svgNode('marker',{id:'debt-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto'});marker.append(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#aaa5bd'}));defs.append(marker);svg.append(defs);
  function node(id,x,y){const n=data.nodes.find(n=>n.id===id),g=svgNode('g',{tabindex:0,role:'button','aria-label':`Inspect ${id}`});g.style.cursor='pointer';g.append(svgNode('rect',{x,y:y-22,width:280,height:44,rx:8,fill:'#181727',stroke:colours[n?.severity||'none'],'stroke-width':2}),svgNode('text',{x:x+12,y:y+4,fill:'#f2effb','font-size':12},id.length>32?id.slice(0,29)+'…':id),svgNode('title',{},`${id}: ${n?.points||0} pts`));const choose=()=>{select.value=id;draw()};g.addEventListener('click',choose);g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose()}});svg.append(g)}
  incoming.slice(0,10).forEach((id,i)=>{const y=45+i*65;svg.append(svgNode('line',{x1:290,y1:y,x2:360,y2:mid,stroke:'#aaa5bd','marker-end':'url(#debt-arrow)'}));node(id,10,y)});
  outgoing.slice(0,10).forEach((id,i)=>{const y=45+i*65;svg.append(svgNode('line',{x1:640,y1:mid,x2:710,y2:y,stroke:'#aaa5bd','marker-end':'url(#debt-arrow)'}));node(id,710,y)});node(selected,360,mid);graph.append(svg);
  for(const[title,ids]of [['Incoming imports',incoming],['Outgoing imports',outgoing]]){const d=make('details');d.append(make('summary',`${title} (${ids.length})`),make('p',ids.join(' · ')||'None in retained graph'));detail.append(d)}
  detail.append(make('p','Graph displays up to 10 neighbours per side; expand lists for all retained connections.','note'));
 }
 select.addEventListener('change',draw);draw();
 box.append(make('p',`Omitted: ${data.omitted_nodes} nodes, ${data.omitted_edges} edges. Invalid/unreadable Python files skipped: ${data.skipped_python_files}.`,'note'));
 return box;
}
