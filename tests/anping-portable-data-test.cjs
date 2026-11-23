'use strict';
// Native host checks; all copies and generated data stay in a uniquely owned project .tmp folder.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');fs.mkdirSync(path.join(root,'.tmp'),{recursive:true});const out=fs.mkdtempSync(path.join(root,'.tmp','portable-data-')),failuresOnly=process.argv.includes('--failure-paths-only');
const first=path.join(out,'program-a'),moved=path.join(out,'program-b'),blocked=path.join(out,'blocked'),denied=path.join(out,'denied'),cwd=path.join(out,'other-cwd'),forbidden=path.join(out,'forbidden-profile');
const old=[path.join(process.env.LOCALAPPDATA,'can-i-delete'),path.join(process.env.LOCALAPPDATA,'CanIDelete')];
const baseline=old.map(p=>fs.existsSync(p));const run=(exe,args,options={})=>cp.execFileSync(exe,args,{cwd,encoding:'utf8',timeout:35000,windowsHide:true,...options});
fs.mkdirSync(cwd);fs.mkdirSync(first);
function setup(dir){fs.mkdirSync(dir,{recursive:true});for(const f of ['can-i-delete.exe','WebView2Loader.dll','ui','lib'])fs.cpSync(path.join(root,f),path.join(dir,f),{recursive:true});}
function noFallback(){assert(!fs.existsSync(forbidden),'external profile folder was written');assert(!fs.existsSync(path.join(cwd,'data')),'cwd used for data');old.forEach((p,i)=>assert.equal(fs.existsSync(p),baseline[i],'old AppData recreated'));}
const env={...process.env,WEBVIEW2_USER_DATA_FOLDER:forbidden,PORTABLE_FORBIDDEN_PROFILE:forbidden};
try{
 setup(first);
 const csc='C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe';
 cp.execFileSync(csc,['-nologo','-codepage:65001','-target:exe','-out:'+path.join(first,'AnPingPortableDataProbe.exe'),...['System.Windows.Forms.dll','System.Drawing.dll','System.Web.Extensions.dll',path.join(root,'can-i-delete.exe'),path.join(root,'lib/Microsoft.Web.WebView2.Core.dll'),path.join(root,'lib/Microsoft.Web.WebView2.WinForms.dll')].map(r=>'-r:'+r),path.join(root,'tools/AnPingPortableDataProbe.cs')],{cwd:root,stdio:'inherit',timeout:20000});
 if(!failuresOnly){
  console.log(run(path.join(first,'AnPingPortableDataProbe.exe'),['first'],{env}));noFallback();
  console.log(run(path.join(first,'AnPingPortableDataProbe.exe'),['reopen'],{env}));noFallback();
 }
 // Move the entire program folder, including its saved settings, instead of resetting a profile.
 const closeDeadline=Date.now()+15000;
 for(;;){try{fs.renameSync(first,moved);break;}catch(e){if(!['EPERM','EBUSY','EACCES'].includes(e.code)||Date.now()>=closeDeadline)throw e;Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,100);}}
 if(!failuresOnly){console.log(run(path.join(moved,'AnPingPortableDataProbe.exe'),['moved'],{env}));noFallback();}
 setup(blocked);fs.copyFileSync(path.join(moved,'AnPingPortableDataProbe.exe'),path.join(blocked,'AnPingPortableDataProbe.exe'));
 fs.writeFileSync(path.join(blocked,'data'),'generated path blocker');
 console.log(run(path.join(blocked,'AnPingPortableDataProbe.exe'),['blocked'],{env}));noFallback();assert.equal(fs.readFileSync(path.join(blocked,'data'),'utf8'),'generated path blocker');
 setup(denied);fs.copyFileSync(path.join(moved,'AnPingPortableDataProbe.exe'),path.join(denied,'AnPingPortableDataProbe.exe'));fs.mkdirSync(path.join(denied,'data'));
 // Restrict only the generated test directory, restoring its ACL even when the child fails.
 const aclScript=`$ErrorActionPreference='Stop'
$p=$env:PORTABLE_DENIED_DATA
$original=[System.IO.Directory]::GetAccessControl($p)
$copy=[System.IO.Directory]::GetAccessControl($p)
$rule=New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().User,[System.Security.AccessControl.FileSystemRights]::Write,[System.Security.AccessControl.AccessControlType]::Deny)
$copy.AddAccessRule($rule)
try { [System.IO.Directory]::SetAccessControl($p, $copy); & $env:PORTABLE_DENIED_EXE blocked; if ($LASTEXITCODE -ne 0) { throw 'denied-path native probe failed' } }
finally { [System.IO.Directory]::SetAccessControl($p, $original) }
`;
 const acl=path.join(out,'deny-generated-data.ps1');fs.writeFileSync(acl,aclScript);
 console.log(run('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',acl],{env:{...env,PORTABLE_DENIED_DATA:path.join(denied,'data'),PORTABLE_DENIED_EXE:path.join(denied,'AnPingPortableDataProbe.exe')}}));noFallback();
 const checks=['file blocker rejected without UI','write-denied rejected without UI','no AppData fallback'];
 if(!failuresOnly)checks.unshift('different cwd','restart','folder relocation with settings','profile env override');
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({passed:true,checks,appDataExisted:baseline},null,2));
 console.log('PASS portable checks: '+checks.join('; '));
 console.log('Evidence: .tmp/portable-data-result.json');
}finally{
 // Only this run's mkdtemp directory is removed; keep the small result, not profiles or program copies.
 const result=path.join(out,'result.json');
 if(fs.existsSync(result))fs.copyFileSync(result,path.join(root,'.tmp','portable-data-result.json'));
 fs.rmSync(out,{recursive:true,maxRetries:10,retryDelay:150});
}
