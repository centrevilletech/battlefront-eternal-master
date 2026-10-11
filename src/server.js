import http from 'node:http';
import { randomBytes, createHash, sign, createPrivateKey, createPublicKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { WebSocketServer, WebSocket } from 'ws';
import ipaddr from 'ipaddr.js';
import { authenticate, turnCredentials } from './auth.js';

const fail=(status,message)=>Object.assign(new Error(message),{status});
const text=(x,n=80)=>{if(typeof x!=='string'||!x.length||x.length>n||/[\x00-\x1f\x7f]/.test(x))throw fail(400,'invalid text');return x;};
const integer=(x,max)=>{if(!Number.isInteger(x)||x<0||x>max)throw fail(400,'invalid count');return x;};
export function address(value) { const ip=ipaddr.process(value);return ip.toNormalizedString(); }
function bucketAddress(value) {const ip=ipaddr.process(value);return ip.kind()==='ipv6'?ip.parts.slice(0,4).join(':'):ip.toString();}
function sameAddress(a,b) {try{return address(a)===address(b);}catch{return false;}}
export function listing(value, owner, caller) {
  const policy=value.relayPolicy??'auto';if(!['auto','never','always'].includes(policy))throw fail(400,'invalid relay policy');
  const endpoints=Array.isArray(value.endpoints)?value.endpoints:[];
  if(endpoints.length>4)throw fail(400,'too many endpoints');
  const safe=policy==='always'?[]:endpoints.map(e=>{
    // Only the source address is accepted without a separate signed reachability proof.
    if(!sameAddress(e.address,caller)||ipaddr.process(e.address).range()!=='unicast')throw fail(400,'endpoint must be public request source');
    if(!['udp','webrtc'].includes(e.transport))throw fail(400,'unsupported endpoint');
    return {address:address(e.address),port:integer(e.port,65535)||(()=>{throw fail(400,'invalid port');})(),transport:e.transport,verified:false};
  });
  const rotation=value.rotation;
  if(!Array.isArray(rotation)||rotation.length<1||rotation.length>64)throw fail(400,'invalid rotation');
  const maps=rotation.map(m=>{text(m,100);if(!/^swbf[12]\/[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_-]+$/.test(m))throw fail(400,'invalid map');return m;});
  const players=integer(value.players,128),maxPlayers=integer(value.maxPlayers,128);if(!maxPlayers||players>maxPlayers)throw fail(400,'invalid player counts');
  const fingerprint=text(value.fingerprint,120);if(!/^sha-256 (?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/.test(fingerprint))throw fail(400,'invalid transport fingerprint');
  return {id:owner.id,publicKey:owner.publicKey,name:text(value.name),protocol:integer(value.protocol,65535),simulation:text(value.simulation,128),content:text(value.content,128),rotation:maps,players,maxPlayers,relayPolicy:policy,endpoints:safe,fingerprint,location:value.location==null?null:text(value.location,80)};
}
export function createMaster(options={}) {
  const now=options.now??Date.now, ttl=60000, maxServers=options.maxServers??2000;
  const db=new DatabaseSync(options.database??':memory:');
  db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, reporter TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS bans(player TEXT PRIMARY KEY, reason TEXT NOT NULL, expires INTEGER NOT NULL);`);
  const servers=new Map(),nonces=new Map(),rates=new Map(),tickets=new Map(),sockets=new Map();
  const noticeVersion=options.noticeVersion??'2026-10-11';
  const trusted=new Set((options.trustedProxies??[]).map(address));
  const signingKey=options.signingKey?createPrivateKey(options.signingKey):null;
  const publicKey=signingKey?createPublicKey(signingKey).export({format:'der',type:'spki'}).toString('base64'):null;
  const wss=new WebSocketServer({noServer:true,maxPayload:32768,perMessageDeflate:false});
  function sweep(){const t=now();for(const [id,s]of servers)if(s.expires<=t)servers.delete(id);for(const m of [nonces,tickets,rates])for(const[k,v]of m)if((typeof v==='number'?v:v.expires)<=t)m.delete(k);db.prepare('DELETE FROM reports WHERE created < ?').run(t-30*86400000);}
  const cleaner=setInterval(sweep,10000);cleaner.unref();
  function caller(req){let ip=address(req.socket.remoteAddress);if(trusted.has(ip)){const forwarded=req.headers['x-real-ip'];if(typeof forwarded!=='string')throw fail(400,'proxy client address missing');try{ip=address(forwarded);}catch{throw fail(400,'invalid proxy address');}}return ip;}
  function limit(key,max=120){const t=now();let item=rates.get(key);if(!item||item.expires<=t){if(rates.size>=20000)throw fail(503,'rate capacity');item={count:0,expires:t+60000};rates.set(key,item);}if(++item.count>max)throw fail(429,'rate limit');}
  function consent(req){if(req.headers['x-bfe-notice']!==noticeVersion)throw fail(428,'online notice acknowledgment required');}
  function send(res,status,data){const body=JSON.stringify(data);res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff','access-control-allow-origin':'*'});res.end(body);}
  async function body(req){const chunks=[];let size=0;for await(const part of req){size+=part.length;if(size>32768)throw fail(413,'request too large');chunks.push(part);}return Buffer.concat(chunks).toString('utf8');}
  function owner(req,raw){try{return authenticate(req,raw,nonces,now());}catch{throw fail(401,'invalid or replayed signature');}}
  const server=http.createServer(async(req,res)=>{try{
    const ip=caller(req),url=new URL(req.url,'http://localhost'),path=url.pathname;
    limit(`ip:${bucketAddress(ip)}`);
    if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,PUT,DELETE,OPTIONS','access-control-allow-headers':'content-type,x-bfe-key,x-bfe-time,x-bfe-nonce,x-bfe-signature,x-bfe-notice'});res.end();return;}
    if(req.method==='GET'&&path==='/healthz')return send(res,200,{ok:true,service:'battlefront-eternal-master',version:'0.1.0'});
    if(req.method==='GET'&&path==='/v1/info')return send(res,200,{name:'Battlefront Eternal',protocol:1,noticeVersion,publicKey,operator:options.operator??'Josh Lambert',contact:options.contact??'https://github.com/joshualambert/battlefront-eternal-master/issues',privacy:{text:'Online play processes your IP address for connectivity and abuse prevention. Independent servers and relays process connection metadata. Location sharing is optional.',ipRetention:'In-memory connection and rate-limit state only; web proxy logs follow the operator policy.',reportsRetentionDays:30},relays:options.turnUrls??[],limits:{heartbeatSeconds:20,expirySeconds:60,httpsOnlyNetworksSupported:false}});
    if(req.method==='GET'&&path==='/v1/whoami'){consent(req);return send(res,200,{address:ip,family:ipaddr.parse(ip).kind()});}
    if(req.method==='GET'&&path==='/v1/servers'){consent(req);sweep();const list=[...servers.values()].map(s=>s.listing);const tag='"'+createHash('sha256').update(JSON.stringify(list)).digest('hex')+'"';res.setHeader('etag',tag);if(req.headers['if-none-match']===tag){res.writeHead(304);res.end();return;}return send(res,200,{servers:list});}
    const match=path.match(/^\/v1\/servers\/([a-f0-9]{64})$/);
    if(req.method==='GET'&&match){consent(req);sweep();const s=servers.get(match[1]);if(!s)throw fail(404,'server not found');return send(res,200,s.listing);}
    if(req.method==='GET'&&path==='/v1/bans'){consent(req);if(!signingKey)throw fail(503,'ban signing unavailable');const payload={issued:now(),expires:now()+300000,bans:db.prepare('SELECT player,reason,expires FROM bans WHERE expires > ?').all(now())};return send(res,200,{payload,signature:sign(null,Buffer.from(JSON.stringify(payload)),signingKey).toString('base64'),publicKey});}
    if(!['POST','PUT','DELETE'].includes(req.method))throw fail(404,'not found');
    consent(req);const raw=await body(req),auth=owner(req,raw);limit(`key:${auth.id}`,120);let data={};try{data=raw?JSON.parse(raw):{};}catch{throw fail(400,'invalid JSON');}if(!data||Array.isArray(data)||typeof data!=='object')throw fail(400,'invalid object');
    if((path==='/v1/servers'&&req.method==='POST')||(match&&req.method==='PUT')){
      if(match&&match[1]!==auth.id)throw fail(403,'not your server');
      if(!servers.has(auth.id)&&servers.size>=maxServers)throw fail(503,'directory full');
      const perAddress=[...servers.values()].filter(s=>s.ip===ip&&s.listing.id!==auth.id).length;if(perAddress>=8)throw fail(429,'server limit for address');
      const item=listing(data,auth,ip);servers.set(auth.id,{listing:item,ip,expires:now()+ttl});return send(res,match?200:201,item);
    }
    if(match&&req.method==='DELETE'){if(match[1]!==auth.id)throw fail(403,'not your server');servers.delete(auth.id);return send(res,200,{ok:true});}
    if(path==='/v1/relay-credentials'&&req.method==='POST'){
      limit(`relay:${auth.id}`,6);limit(`relay-ip:${bucketAddress(ip)}`,24);
      if(!options.turnSecret||!options.turnUrls?.length)throw fail(503,'relay unavailable');
      const target=typeof data.serverId==='string'&&servers.get(data.serverId);
      if(!target||target.expires<=now())throw fail(404,'register or select an active server first');
      if(target.listing.relayPolicy==='never')throw fail(403,'server disables relay');
      return send(res,200,{...turnCredentials(options.turnSecret,auth.id,now()),urls:options.turnUrls});
    }
    if(path==='/v1/signal-ticket'&&req.method==='POST'){
      limit(`ticket:${auth.id}`,6);if(tickets.size>=4096)throw fail(503,'signaling full');const ticket=randomBytes(32).toString('base64url');tickets.set(ticket,{id:auth.id,expires:now()+30000});return send(res,200,{ticket,expires:now()+30000});
    }
    if(path==='/v1/reports'&&req.method==='POST'){
      limit(`report:${auth.id}`,3);limit(`report-ip:${bucketAddress(ip)}`,10);
      if(!/^[a-f0-9]{64}$/.test(data.target))throw fail(400,'invalid target');
      const total=db.prepare('SELECT count(*) n FROM reports').get().n;if(total>=100000)throw fail(503,'report capacity');
      db.prepare('INSERT INTO reports(reporter,target,reason,created) VALUES(?,?,?,?)').run(auth.id,data.target,text(data.reason,1000),now());return send(res,201,{ok:true});
    }
    throw fail(404,'not found');
  }catch(error){if(!res.headersSent)send(res,error.status??500,{error:error.status?error.message:'internal error'});else res.destroy();}});
  server.requestTimeout=10000;server.headersTimeout=10000;server.maxHeadersCount=40;
  server.on('upgrade',(req,socket,head)=>{try{const url=new URL(req.url,'http://localhost');if(url.pathname!=='/v1/signal')throw Error();limit(`ws:${bucketAddress(caller(req))}`,30);const token=url.searchParams.get('ticket'),ticket=tickets.get(token);tickets.delete(token);if(!ticket||ticket.expires<=now()||sockets.size>=4096)throw Error();wss.handleUpgrade(req,socket,head,ws=>{sockets.get(ticket.id)?.close(4000,'replaced');sockets.set(ticket.id,ws);ws.alive=true;
    ws.on('pong',()=>ws.alive=true);
    ws.on('message',(raw,isBinary)=>{try{if(isBinary)throw Error();limit(`signal:${ticket.id}`,180);const message=JSON.parse(raw.toString());if(!/^[a-f0-9]{64}$/.test(message.to)||!['offer','answer','candidate','reject'].includes(message.type)||typeof message.payload!=='string'||message.payload.length>24000)throw Error();
      // A client may contact a listed server. Replies require an existing offer route.
      const route=`route:${message.to}:${ticket.id}`,outbound=`route:${ticket.id}:${message.to}`;
      if(message.type==='offer'){const target=servers.get(message.to);if(!target||target.expires<=now())throw Error();if(routes.size>=10000)throw Error();routes.set(outbound,now()+120000);}else if((routes.get(route)??0)<=now()&&(routes.get(outbound)??0)<=now())throw Error();
      const target=sockets.get(message.to);if(!target||target.readyState!==WebSocket.OPEN)return;if(target.bufferedAmount>65536){target.close(4008,'backpressure');return;}target.send(JSON.stringify({from:ticket.id,type:message.type,payload:message.payload}));
    }catch{ws.close(1008,'invalid signal');}});ws.on('error',()=>{});ws.on('close',()=>{if(sockets.get(ticket.id)===ws)sockets.delete(ticket.id);});});}catch{socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');}});
  const routes=new Map();const heartbeat=setInterval(()=>{for(const ws of sockets.values()){if(!ws.alive)ws.terminate();else{ws.alive=false;ws.ping();}}for(const[k,v]of routes)if(v<=now())routes.delete(k);},30000);heartbeat.unref();
  return {server,db,servers,sweep,async close(){clearInterval(cleaner);clearInterval(heartbeat);for(const ws of sockets.values())ws.terminate();wss.close();await new Promise(r=>server.close(r));db.close();}};
}
