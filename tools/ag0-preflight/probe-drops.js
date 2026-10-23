const fs=require('fs'),path=require('path');
const {buildArgs}=require('../../lib/facts/cmdline');
const SRC='D:/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony';
const parts=['account','communication','notification','accesscontrol'];
function scan(file,on){const CH=1<<20;const fd=fs.openSync(file,'r');const b=Buffer.alloc(CH);let carry='';
 for(;;){const n=fs.readSync(fd,b,0,CH,null);if(n<=0)break;const text=carry+b.toString('utf8',0,n);let inS=false,esc=false,d=0,s=-1;
  for(let i=0;i<text.length;i++){const c=text[i];
   if(inS){if(esc){esc=false;continue}if(c==='\\'){esc=true;continue}if(c==='"')inS=false;continue}
   if(c==='"'){inS=true;continue}
   if(c==='{'){if(d===0)s=i;d++;continue}
   if(c==='}'){d--;if(d===0&&s>=0){on(JSON.parse(text.slice(s,i+1)));s=-1}continue}}
  carry=s>=0?text.slice(s):''}
 fs.closeSync(fd)}
let entries=0, defineDrops=0, flagDrops=0, merged=0, zeroArgs=0;
const dropSample=new Map();
for(const p of parts){scan(path.join(SRC,'out','rk3568','compdb_parts',p,'compile_commands.json'),(e)=>{
  entries++;
  const {args,dropped,mergedDefines}=buildArgs(String(e.command||''));
  merged+=mergedDefines;
  if(!args.length)zeroArgs++;
  for(const d of dropped){
    if(/^-D/.test(d)){defineDrops++;dropSample.set(d,(dropSample.get(d)||0)+1)}
    else flagDrops++;
  }
});}
console.log(JSON.stringify({entries,defineDrops,flagDrops,mergedDefineGroups:merged,zeroArgs,defineDropSample:[...dropSample].slice(0,10)},null,2));
