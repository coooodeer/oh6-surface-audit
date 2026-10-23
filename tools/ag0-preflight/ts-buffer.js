const path=require('path'),fs=require('fs');
const MOD='D:/oh6.0/OpenHarmony-v6.0-Release/oh6-framework-want-leak-miner/node_modules';
const Parser=require(path.join(MOD,'tree-sitter'));
const Cpp=require(path.join(MOD,'tree-sitter-cpp'));
const p=new Parser(); p.setLanguage(Cpp);
const f='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/base/account/os_account/frameworks/osaccount/core/src/os_account.cpp';
const text=fs.readFileSync(f,'utf8');
for(const bs of [null, 64*1024, 1024*1024]){
  const t0=Date.now();
  try{
    const t = bs===null? p.parse(text) : p.parse(text, null, {bufferSize: bs});
    console.log('bufferSize='+bs, 'ok', 'hasError='+t.rootNode.hasError, 'nodes(children)='+t.rootNode.namedChildCount, 'ms='+(Date.now()-t0));
  }catch(e){ console.log('bufferSize='+bs, 'FAIL', String(e.message||e)); }
}
// 大文件 + bufferSize
const big='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/foundation/communication/dsoftbus/core/bus_center/lnn/lane_hub/lane_manager/src/lnn_lane_link_p2p.c';
const C=require(path.join(MOD,'tree-sitter-c'));
const p2=new Parser(); p2.setLanguage(C);
const t2=fs.readFileSync(big,'utf8');
for(const bs of [null, 1024*1024]){
  try{
    const t = bs===null? p2.parse(t2) : p2.parse(t2, null, {bufferSize: bs});
    console.log('C bufferSize='+bs,'ok','hasError='+t.rootNode.hasError,'bytes='+Buffer.byteLength(t2));
  }catch(e){ console.log('C bufferSize='+bs,'FAIL',String(e.message||e)); }
}
