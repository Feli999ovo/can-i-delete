'use strict';
// 清理结果与锁定的前端回归（DOM 替身，非截图）。复用 anping-ui-test 的页面加载与 receive()。
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const file=path.join(__dirname,'anping-ui-test.cjs');
const extra=String.raw`
context.showCleanProblems=(msg,lead,title)=>{context.problemLead=lead;context.problemTitle=title;};
context.drawerOpen=false;
const remaining={id:'dump',name:'crash dumps',ok:0.01,review:0,keep:0,total:0.01,count:1,files:[]};
const send=m=>receive(Object.assign({action:'cleanResult',request:context.S.cleanRequest},m));
context.S.cleanRequest=500;context.S.cleaning=true;
send({deleted:0,freedBytes:0,attempted:1,unknown:1,untouched:0,changed:0,stillPresent:0,notExecuted:0,locked:true,categories:[remaining],problems:[]});
assert(!context.S.freedNote.includes('已保留原样'),'未知结果不能说已保留');
assert(context.S.freedNote.includes('1 个结果无法确认'));
assert(context.problemLead.includes('可能已删除，也可能还在'));
assert.equal(context.S.cleanLocked,true);
console.log('PASS unknown result -> no preserved claim, cleaning locked');

context.S.cleanRequest=501;
receive({action:'cleanResult',request:400,deleted:1,freedBytes:44,attempted:1,categories:[remaining]});
assert.equal(context.S.cleanRequest,501,'旧请求的结果必须被丢弃');
console.log('PASS stale cleanResult ignored');

context.S.cleanLocked=false;
send({deleted:0,freedBytes:0,attempted:2,unknown:0,untouched:1,changed:1,stillPresent:0,notExecuted:0,categories:[remaining],problems:[{name:'a',detail:'目标已消失'}]});
assert(context.S.freedNote.includes('1 个未删除（原文件未动）'));
assert(context.S.freedNote.includes('1 个已跳过（扫描后已消失或被改动）'));
console.log('PASS untouched vs changed reported separately');

receive({action:'pendingClean',count:2,items:[{name:'x.dmp',exists:false}],log:'L'});
assert.equal(context.S.cleanLocked,true);assert.equal(context.problemTitle,'上次清理未完成');
console.log('PASS pending records from an interrupted run lock cleaning');

context.S.cleaning=true;context.S.cleanRequest=600;
receive({action:'cleanProgress',request:600,done:3,total:9});
assert.deepEqual(JSON.parse(JSON.stringify(context.S.cleanProg)),{done:3,total:9});
receive({action:'cleanProgress',request:599,done:8,total:9});
assert.equal(context.S.cleanProg.done,3,'旧请求的进度被忽略');
console.log('PASS progress tracked per request (rendering checked in the native probe)');
`;
const m=new Module(file,module);m.filename=file;m.paths=Module._nodeModulePaths(path.dirname(file));
m._compile(fs.readFileSync(file,'utf8')+'\n'+extra,file);
