/* Original synthesized porcelain cues. No samples, files, or OS sound settings. */
(function(global){
'use strict';
var CUES={
 hover:{duration:.055,notes:[{at:0,duration:.055,frequency:1850,gain:.018,partial:2.05}]},
 click:{duration:.110,notes:[{at:0,duration:.110,frequency:1420,gain:.030,partial:2.08}]},
 complete:{duration:.440,notes:[{at:0,duration:.180,frequency:784,gain:.025,partial:2},{at:.240,duration:.200,frequency:1046.5,gain:.025,partial:2}]}
};
function Controller(options){this.options=options||{};this.enabled=false;this.context=null;this.nodes=new Set();this.generation=0;this.session=null;this.notified=null;this.pending=null;this.lastHover=-Infinity;this.lastResult={status:'muted'};}
Controller.prototype.report=function(status,kind,session){this.lastResult={status:status,kind:kind,session:session};if(this.options.onResult)this.options.onResult(this.lastResult);return status==='scheduled';};
Controller.prototype.cancel=function(){this.generation++;this.pending=null;this.nodes.forEach(function(n){try{n.stop();}catch(_){}});this.nodes.clear();};
Controller.prototype.setEnabled=function(value){this.enabled=!!value;if(!this.enabled)this.cancel();this.report(this.enabled?'enabled':'muted');};
Controller.prototype.beginSession=function(id){this.cancel();this.session=id;this.notified=null;this.lastHover=-Infinity;};
Controller.prototype.stopSession=function(){this.cancel();this.session=null;};
Controller.prototype.prepare=async function(){
 if(!this.context||this.context.state==='closed')this.context=this.options.createContext?this.options.createContext():new (global.AudioContext||global.webkitAudioContext)();
 var ctx=this.context;
 if(ctx.state==='suspended'){
  var timer;try{await Promise.race([ctx.resume(),new Promise(function(_,reject){timer=setTimeout(function(){reject(new Error('resume-timeout'));},800);})]);}finally{clearTimeout(timer);}
 }
 return ctx;
};
// 恢复已保存的开启状态后，在真实点击/按键中解锁，避免扫描结束才首次创建上下文。
Controller.prototype.unlock=function(){if(!this.enabled)return;var self=this;this.prepare().then(function(ctx){if(self.enabled&&ctx.state!=='running')self.report('resume-failed','unlock',self.session);},function(e){if(self.enabled)self.report(e&&e.message==='resume-timeout'?'resume-timeout':'schedule-or-resume-failed','unlock',self.session);});};
Controller.prototype.play=async function(kind,id){
 var cue=CUES[kind],self=this,token=this.generation;
 if(!cue)return this.report('invalid-event',kind,id);
 if(!this.enabled)return this.report('muted',kind,id);
 if(kind==='complete'&&(id!==this.session||id===this.notified||this.pending===id))return this.report('stale-or-duplicate',kind,id);
 var now=this.options.now?this.options.now():performance.now();if(kind==='hover'&&now-this.lastHover<120)return this.report('throttled',kind,id);if(kind==='hover')this.lastHover=now;
 if(kind==='complete')this.pending=id;
 var sources=[];
 try {
  var ctx=await this.prepare();
  if(!this.enabled||token!==this.generation||(kind==='complete'&&id!==this.session))return this.report('cancelled',kind,id);
  if(ctx.state!=='running')return this.report('resume-failed',kind,id);
  var start=ctx.currentTime+.015;
  cue.notes.forEach(function(note){
   [1,note.partial].forEach(function(ratio,i){var oscillator=ctx.createOscillator(),gain=ctx.createGain(),at=start+note.at;oscillator.type='sine';oscillator.frequency.setValueAtTime(note.frequency*ratio,at);gain.gain.setValueAtTime(0,at);gain.gain.linearRampToValueAtTime(note.gain*(i===0?1:.16),at+.004);gain.gain.linearRampToValueAtTime(note.gain*(i===0?1:.16)*.5,at+note.duration*.6);gain.gain.exponentialRampToValueAtTime(.00001,at+note.duration);gain.gain.setValueAtTime(0,at+note.duration+.002);oscillator.connect(gain);gain.connect(ctx.destination);sources.push(oscillator);self.nodes.add(oscillator);oscillator.onended=function(){self.nodes.delete(oscillator);oscillator.disconnect();gain.disconnect();};oscillator.start(at);oscillator.stop(at+note.duration+.004);});
  });
  if(kind==='complete')this.notified=id;
  if(this.options.onScheduled)this.options.onScheduled({kind:kind,session:id,start:start,notes:cue.notes.map(function(n){return {at:n.at,duration:n.duration,frequency:n.frequency};}),duration:cue.duration});
  return this.report('scheduled',kind,id);
 }catch(error){sources.forEach(function(n){try{n.stop();}catch(_){}});if(!this.enabled||token!==this.generation)return this.report('cancelled',kind,id);return this.report(error&&error.message==='resume-timeout'?'resume-timeout':'schedule-or-resume-failed',kind,id);}
 finally{if(kind==='complete'&&token===this.generation&&this.pending===id)this.pending=null;}
};
global.AnPingAudio={Controller:Controller,cues:CUES};
})(typeof window==='undefined'?globalThis:window);
