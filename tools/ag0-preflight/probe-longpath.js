const fs=require('fs'),path=require('path');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile()&&/\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name))a.push(p);}}
const files=[];for(const r of ROOTS)walk(path.join(SRC,r),files);
let over260=0,max=0,maxFile='';
for(const f of files){const n=f.length; if(n>max){max=n;maxFile=f;} if(n>260)over260++;}
console.log(JSON.stringify({files:files.length,over260,max,maxFile:maxFile.replace(SRC+'\\','').slice(0,120)},null,2));
