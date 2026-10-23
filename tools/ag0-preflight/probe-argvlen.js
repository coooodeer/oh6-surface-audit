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
let n=0, over=0, max=0, sum=0; const hist={};
for(const p of parts){scan(path.join(SRC,'out/rk3568/compdb_parts',p,'compile_commands.json'),(e)=>{
  const {args}=buildArgs(String(e.command||''));
  // 路径从 /mnt/d 改写成 D:/，长度基本不变（少 6 字符/TU）
  const len=args.reduce((a,b)=>a+b.length+3,0);
  n++; sum+=len; if(len>max)max=len;
  if(len>30000)over++;
  const k=len>30000?'>30k':len>20000?'>20k':len>10000?'>10k':'<=10k';
  hist[k]=(hist[k]||0)+1;
});}
console.log(JSON.stringify({entries:n,avgChars:Math.round(sum/n),maxChars:max,over30k:over,overRatio:Number((over/n).toFixed(3)),hist},null,2));

