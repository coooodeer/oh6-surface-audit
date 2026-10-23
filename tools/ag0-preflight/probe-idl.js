const fs=require('fs'),path=require('path');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile()&&e.name.endsWith('.idl'))a.push(p);}}
const files=[];for(const r of ROOTS)walk(path.join(SRC,r),files);
let withCode=0, methods=0, ifaces=0; const rows=[];
for(const f of files){const t=fs.readFileSync(f,'utf8');
  const mIface=(t.match(/^\s*interface\s+([\w.]+)/gm)||[]).length;
  const mTok=(t.match(/\[ipccode\s+0x[0-9a-fA-F]+/g)||[]).length;
  const mMethod=(t.match(/^\s*(?:\[[^\]]*\]\s*)?[A-Za-z_][\w.<>, \[\]]*\s+([A-Za-z_]\w*)\s*\(/gm)||[]).length;
  ifaces+=mIface; methods+=mMethod; if(mTok)withCode++;
  rows.push({file:path.relative(SRC,f).split(path.sep).join('/').replace('OpenHarmony/',''), iface:mIface, ipccode:mTok, methods:mMethod});
}
console.log(JSON.stringify({files:files.length,withIpccode:withCode,ifaces,methods,rows},null,2));
