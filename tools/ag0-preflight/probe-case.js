const fs=require('fs'),path=require('path');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile())a.push(p);}}
const all=[];for(const r of ROOTS)walk(path.join(SRC,r),all);
const seen=new Map();let collide=0;const samples=[];
for(const f of all){const k=f.toLowerCase();if(seen.has(k)&&seen.get(k)!==f){collide++;if(samples.length<5)samples.push([seen.get(k).slice(SRC.length+1),f.slice(SRC.length+1)]);}else seen.set(k,f);}
console.log(JSON.stringify({allFiles:all.length,caseCollisions:collide,samples},null,2));
