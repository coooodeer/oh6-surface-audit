const fs=require('fs'),path=require('path');
const MOD='D:/oh6.0/OpenHarmony-v6.0-Release/oh6-framework-want-leak-miner/node_modules';
const Parser=require(path.join(MOD,'tree-sitter'));
const Cpp=require(path.join(MOD,'tree-sitter-cpp'));
const C=require(path.join(MOD,'tree-sitter-c'));
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const ROOTS=['base/account/os_account','foundation/communication/dsoftbus','foundation/communication/ipc','base/notification/eventhandler','base/accesscontrol/sandbox_manager'];
const SKIP=new Set(['.git','node_modules','third_party','prebuilts','out','build']);
function walk(d,a){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()){if(!SKIP.has(e.name))walk(p,a);}else if(e.isFile()&&/\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name))a.push(p);}}
const files=[];for(const r of ROOTS)walk(path.join(SRC,r),files);
const p=new Parser();
let n=0;const t0=Date.now();
for(const f of files){
  const text=fs.readFileSync(f,'utf8');
  p.setLanguage(f.toLowerCase().endsWith('.c')?C:Cpp);
  let t;
  try{ t=p.parse(text,null,{bufferSize:1024*1024}); }catch(e){ console.log('fail',f,e.message); continue; }
  n++;
  if(typeof t.delete==='function') t.delete();
  if(n%500===0) console.log('n='+n,'rssMB='+Math.round(process.memoryUsage().rss/1048576),'ms='+(Date.now()-t0));
}
console.log('done n='+n,'rssMB='+Math.round(process.memoryUsage().rss/1048576),'totalMs='+(Date.now()-t0),'hasDelete='+(typeof p.parse('int x;').delete));
