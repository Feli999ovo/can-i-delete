// Loaded only into the isolated native probe's page closure, never shipped.
window.__motion = {
  scanDone:false, filtersDone:false, recording:false,
  result:{filters:[],frames:[],arrivals:[],reducedMotion:false},
  startScan(path){window.chrome.webview.postMessage(JSON.stringify({action:'startScan',targets:[path]}));},
  async filters(){
    const sleep=ms=>new Promise(r=>setTimeout(r,ms));
    for(const key of ['ok','review','keep','all','ok','all']){
      const tabs=drawer.querySelector('.seg-ctl'), head=drawer.querySelector('.dhead');
      const measure=()=>({text:drawer.querySelector('.seg-ctl').textContent,total:drawer.querySelector('.dtot').textContent,
        rects:Array.from(drawer.querySelectorAll('[data-f]'),b=>{const r=b.getBoundingClientRect();return [r.x,r.y,r.width,r.height];}),
        sameTabs:tabs===drawer.querySelector('.seg-ctl'),sameHead:head===drawer.querySelector('.dhead')});
      const before=measure();drawer.querySelector('[data-f="'+key+'"]').click();const during=measure();
      const busyList=$('flist').inert&&$('flist').getAttribute('aria-busy')==='true';
      const start=performance.now();while(dState.loading&&performance.now()-start<3000)await sleep(10);
      await sleep(220);const after=measure();
      const shift=Math.max(...before.rects.flatMap((r,i)=>r.flatMap((v,j)=>[Math.abs(v-during.rects[i][j]),Math.abs(v-after.rects[i][j])])));
      this.result.filters.push({key,before,during,after,shift,busyList,loaded:!dState.loading&&!$('flist').inert,
        validRows:!dState.page.files.some(f=>key!=='all'&&f.j!==key),rows:drawer.querySelectorAll('.file').length});
    }
    // Rapid clicks and the keyboard must finish on the latest filter, not a late reply.
    ['ok','review','keep','all'].forEach(k=>drawer.querySelector('[data-f="'+k+'"]').click());
    while(dState.loading)await sleep(10);
    this.result.rapid=dState.filter==='all'&&dState.page.total===240;
    drawer.querySelector('[data-f="all"]').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}));
    while(dState.loading)await sleep(10);await sleep(50);
    this.result.keyboard=dState.filter==='ok'&&dState.page.files.every(f=>f.j==='ok')&&document.activeElement.dataset.f==='ok';
    // Empty search, next page and detail/back must keep native IDs and current scope.
    const search=$('fileSearch');search.value='no-such-generated-file';search.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    while(dState.loading)await sleep(10);
    this.result.emptySearch=dState.page.total===0&&drawer.querySelectorAll('.file').length===0;
    search.value='';search.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));while(dState.loading)await sleep(10);
    drawer.querySelector('[data-f="all"]').click();while(dState.loading)await sleep(10);
    $('pageNext').click();while(dState.loading)await sleep(10);
    this.result.paging=dState.page.offset===100&&drawer.querySelectorAll('.file').length<=100;
    const key=drawer.querySelector('.file').dataset.k;drawer.querySelector('.fhead').click();$('detailBack').click();
    this.result.detailBack=document.activeElement.closest('.file')?.dataset.k===key;
    drawer.querySelector('[data-f="ok"]').click();while(dState.loading)await sleep(10);
    // Representative long counts are injected into the page, not invented scan findings.
    dState.page.counts={all:14520,ok:880,review:3847,keep:9793};drawRender();
    const rects=Array.from(drawer.querySelectorAll('[data-f]'),b=>b.getBoundingClientRect());
    this.result.longCounts=rects.every((r,i)=>!i||Math.abs(r.width-rects[0].width)<.5)&&Array.from(drawer.querySelectorAll('[data-f]')).every(b=>b.scrollWidth<=b.clientWidth);
    const oldScale=nativeTextScale;nativeTextScale=2;document.documentElement.style.setProperty('--ts',textScale());
    this.result.scaledTabLines=Array.from(drawer.querySelectorAll('[data-f]')).every(b=>{
      if(b.children.length!==2)return false;
      const [label,count]=Array.from(b.children,e=>e.getBoundingClientRect());
      return count.top>=label.bottom&&b.scrollWidth<=b.clientWidth;
    });
    nativeTextScale=oldScale;document.documentElement.style.setProperty('--ts',textScale());
    this.filtersDone=true;
  },
  progress(i){
    const cats=['pkg','tmp','thumb','user','dump','log'].slice(0,Math.min(6,2+Math.floor(i/2))).map((id,j)=>{
      const total=(1+j*.18)*(1+i*.15)*(j===i%5?2:1),p=i%2?.75:.25;
      return {id,name:id,total,ok:total*(1-p),review:total*p*.7,keep:total*p*.3,count:20+i,files:[]};
    });
    return {action:'scanProgress',scanSessionId:88001,categories:cats,analyzed:i,fileCount:i,currentPath:'generated animation sequence'};
  },
  sample(){return slots.filter(s=>s.g).map(s=>{const r=s.block.getBoundingClientRect();return {id:s.g.id,x:r.x,h:r.height,ratio:r.height? s.segs[1].getBoundingClientRect().height/r.height:0,keep:r.height?s.segs[2].getBoundingClientRect().height/r.height:0};});},
  beginBars(){this.recording=true;const tick=t=>{if(!this.recording)return;this.result.frames.push({t,bars:this.sample()});requestAnimationFrame(tick);};requestAnimationFrame(tick);},
  recordArrival(before){
    let ratioJump=0,positionJump=0;
    this.sample().forEach(b=>{const p=before.find(x=>x.id===b.id);if(p&&p.h>20&&b.h>20){ratioJump=Math.max(ratioJump,Math.abs(p.ratio-b.ratio),Math.abs(p.keep-b.keep));positionJump=Math.max(positionJump,Math.abs(p.x-b.x));}});
    this.result.arrivals.push({ratioJump,positionJump});
  },
  endBars(){this.recording=false;this.result.springCount=springs.length;
    const frames=this.result.frames,dt=frames.slice(1).map((f,i)=>f.t-frames[i].t).sort((a,b)=>a-b);
    this.result.frameTiming={p95:dt[Math.floor(dt.length*.95)],max:Math.max(...dt),over50ms:dt.filter(t=>t>50).length};
    this.result.intermediateRatio=frames.some(f=>f.bars.some(b=>b.ratio>.2&&b.ratio<.45));
    this.result.settled=slots.filter(s=>s.g).every(s=>Math.abs(s.h.x-s.h.t)<.2&&(!s.shift||Math.abs(s.shift.x)<.2)&&(!s.mix||s.mix.every(x=>Math.abs(x.x-x.t)<.2)));
  },
  reduceCheck(){const before=RM;RM=true;renderBars();this.result.reducedMotion=slots.every(s=>s.h.x===s.h.t&&(!s.mix||s.mix.every(x=>x.x===x.t)));RM=before;},
  summary(){const f=this.result.filters,arr=this.result.arrivals;return {filters:f.map(x=>({key:x.key,shift:x.shift,sameTabs:x.during.sameTabs&&x.after.sameTabs,sameHead:x.during.sameHead&&x.after.sameHead,countsStable:x.before.text===x.during.text&&x.before.text===x.after.text,titleStable:x.before.total===x.during.total,validRows:x.validRows,busyList:x.busyList,loaded:x.loaded})),
    maxRatioJump:Math.max(0,...arr.map(x=>x.ratioJump)),maxPositionJump:Math.max(0,...arr.map(x=>x.positionJump)),frames:this.result.frames.length,frameTiming:this.result.frameTiming,rapid:this.result.rapid,keyboard:this.result.keyboard,paging:this.result.paging,detailBack:this.result.detailBack,emptySearch:this.result.emptySearch,longCounts:this.result.longCounts,scaledTabLines:this.result.scaledTabLines,intermediateRatio:this.result.intermediateRatio,settled:this.result.settled,reducedMotion:this.result.reducedMotion};},
  passed(){const s=this.summary();return s.filters.every(x=>x.shift<.5&&x.sameTabs&&x.sameHead&&x.countsStable&&x.titleStable&&x.validRows&&x.busyList&&x.loaded)&&s.maxRatioJump<.08&&s.maxPositionJump<2&&s.frames>25&&s.reducedMotion&&s.rapid&&s.keyboard&&s.paging&&s.detailBack&&s.emptySearch&&s.longCounts&&s.scaledTabLines&&s.intermediateRatio&&s.settled;}
};
window.chrome.webview.addEventListener('message',e=>{
  const m=typeof e.data==='string'?JSON.parse(e.data):e.data;
  if(m.action==='scanComplete')window.__motion.scanDone=true;
});
