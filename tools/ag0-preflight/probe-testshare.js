const fs=require('fs'),path=require('path');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile()&&/\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name))a.push(p);}}
let total=0,test=0,byRoot={};
for(const r of ROOTS){const a=[];walk(path.join(SRC,r),a);let t=0;
 for(const f of a){const rel=f.slice(SRC.length+1).split(path.sep).join('/');
  if(/\/(test|tests|unittest|fuzztest|mock|moduletest|systemtest)\//i.test(rel)||/_(test|unittest|fuzzer|mock)\.(c|cc|cpp)$/i.test(rel))t++;}
 byRoot[r]={files:a.length,test:t};total+=a.length;test+=t;}
console.log(JSON.stringify({total,test,production:total-test,byRoot},null,2));
