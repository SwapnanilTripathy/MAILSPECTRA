import assert from 'node:assert/strict';
import axios from 'axios';
import {createServer} from 'vite';
const values=new Map([['deeptrace_token','expired-synthetic']]);
globalThis.sessionStorage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
let expired=0,refreshes=0,deny=false;
globalThis.window={dispatchEvent:()=>expired++};
axios.defaults.adapter=async config=>{
  if(config.url.endsWith('/auth/refresh')) {
    refreshes++;
    assert.equal(config.withCredentials,true);
    assert.equal(config.headers['X-Mailspectra-CSRF'],'1');
    if(!deny) return {data:{access_token:'rotated-synthetic'},status:200,headers:{},config};
  } else if(config.headers.Authorization==='Bearer rotated-synthetic') return {data:{username:'synthetic'},status:200,headers:{},config};
  throw Object.assign(new Error('Unauthorized'),{config,response:{status:401,data:{}}});
};
const server=await createServer({server:{middlewareMode:true},appType:'custom',optimizeDeps:{noDiscovery:true,include:[]}});
try {
 const {default:api}=await server.ssrLoadModule('/src/api/client.js');
 const results=await Promise.all([api.getCurrentUser(),api.getCurrentUser()]);
 assert.equal(refreshes,1);assert.equal(results[0].username,'synthetic');assert.equal(expired,0);
 values.set('deeptrace_token','expired-synthetic');deny=true;
 await assert.rejects(api.getCurrentUser());assert.equal(values.has('deeptrace_token'),false);assert.equal(expired,1);
 console.log('2 frontend refresh lifecycle checks passed');
} finally {await server.close();}
