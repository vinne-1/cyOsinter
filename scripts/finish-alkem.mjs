import { execFileSync } from "node:child_process";
const BASE="http://localhost:5050", WS="32ba862a-6781-4db9-bc56-2c448d8b274a";
const curl=(a)=>execFileSync("curl",["-s",...a],{encoding:"utf8",maxBuffer:64e6});
const api=(m,p,t,b)=>{const a=["-X",m,`${BASE}${p}`,"-H","Content-Type: application/json"];if(t)a.push("-H",`Authorization: Bearer ${t}`);if(b)a.push("-d",JSON.stringify(b));try{return JSON.parse(curl(a))}catch{return{}}};
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const t=api("POST","/api/auth/login",null,{email:"admin@cyshield.local",password:"ChangeMe123!"}).token;
let st="running";
for(let i=0;i<40;i++){const s=(api("GET",`/api/workspaces/${WS}/scans`,t).data||[])[0];st=s?.status;if(st==="completed"||st==="failed"){console.log("scan",st,"summary",JSON.stringify(s?.summary));break;}await sleep(6000);}
const rep=api("POST",`/api/workspaces/${WS}/reports`,t,{title:"alkemlabs coverage validation",type:"full_report"});
const rid=rep.id;console.log("reportId",rid);
let rs="draft";for(let i=0;i<40;i++){await sleep(3000);const r=api("GET",`/api/reports/${rid}`,t);rs=r.status||rs;if(rs==="completed")break;if(rs==="draft"&&i>3)break;}
console.log("report",rs);
const code=curl(["-X","GET",`${BASE}/api/workspaces/${WS}/reports/${rid}/export?format=docx&evidence=1`,"-H",`Authorization: Bearer ${t}`,"-o","./live-report-alkem.docx","-w","%{http_code}"]);
console.log("export http",code);
