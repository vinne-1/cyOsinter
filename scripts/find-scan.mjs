import { execFileSync } from "node:child_process";
const BASE="http://localhost:5050";
const curl=(a)=>execFileSync("curl",["-s",...a],{encoding:"utf8",maxBuffer:64e6});
const api=(m,p,t,b)=>{const a=["-X",m,`${BASE}${p}`,"-H","Content-Type: application/json"];if(t)a.push("-H",`Authorization: Bearer ${t}`);if(b)a.push("-d",JSON.stringify(b));try{return JSON.parse(curl(a))}catch{return{}}};
const t=api("POST","/api/auth/login",null,{email:"admin@cyshield.local",password:"ChangeMe123!"}).token;
const ws=api("GET","/api/workspaces",t);
const list=ws.data||ws||[];
const alkem=list.filter(w=>(w.name||"").includes("alkemlabs")).sort((a,b)=>new Date(b.createdAt||0)-new Date(a.createdAt||0))[0];
if(!alkem){console.log("no alkem workspace");process.exit(0);}
console.log("workspace",alkem.id,alkem.name);
const scans=api("GET",`/api/workspaces/${alkem.id}/scans`,t);
const s=(scans.data||[])[0];
console.log("latest scan:",s?.status,"pct",s?.progressPercent,"findings",s?.findingsCount);
console.log("WS_ID="+alkem.id);
