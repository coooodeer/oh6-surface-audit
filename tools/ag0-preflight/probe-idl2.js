const fs=require('fs'),path=require('path');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile()&&e.name.endsWith('.idl'))a.push(p);}}
const files=[];for(const r of ROOTS)walk(path.join(SRC,r),files);
let tok=0,code=0,seq=0,raw=0,oneway=0,methods=0;
for(const f of files){const t=fs.readFileSync(f,'utf8');
 if(/^\s*interface_token\s+\S+/m.test(t))tok++;
 if(/\[ipccode\s+0x[0-9a-fA-F]+/.test(t))code++;
 if(/^\s*sequenceable\s+/m.test(t))seq++;
 if(/^\s*rawdata\s+/m.test(t))raw++;
 oneway+=(t.match(/\boneway\b/g)||[]).length;
 methods+=(t.match(/^\s*(?:\[[^\]]*\]\s*)?[A-Za-z_][\w.<>, \[\]]*\s+[A-Za-z_]\w*\s*\(/gm)||[]).length;
}
console.log(JSON.stringify({files:files.length,withInterfaceToken:tok,withIpccode:code,withSequenceable:seq,withRawdata:raw,onewayCount:oneway,methodDecls:methods},null,2));
