import { test } from "node:test";
import assert from "node:assert/strict";
import { identity, signedHeaders } from "../src/auth.js";
import { createMaster } from "../src/server.js";
const entry = {
  name: "Test",
  protocol: 1,
  simulation: "test",
  content: "test",
  rotation: ["swbf1/nab2:rep:conquest"],
  players: 0,
  maxPlayers: 32,
  relayPolicy: "auto",
  endpoints: [],
  fingerprint: "sha-256 " + Array(32).fill("AB").join(":"),
};
async function fixture(t) {
  let now = Date.now();
  const app = createMaster({
    now: () => now,
    turnSecret: "test-secret",
    turnUrls: ["turn:localhost:3478"],
    signingKey: identity().privateKey,
  });
  await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
  t.after(() => app.close());
  const base = `http://127.0.0.1:${app.server.address().port}`,
    keys = identity();
  const request = (path, method = "GET", value, who = keys, extra = {}) => {
    const body = value === undefined ? "" : JSON.stringify(value);
    return fetch(base + path, {
      method,
      headers: {
        "x-bfe-notice": "2026-10-11",
        ...signedHeaders(who, method, path, body, now),
        ...extra,
      },
      body: body || undefined,
    });
  };
  return { app, base, keys, request, advance: (ms) => (now += ms) };
}
test("signed registration, ownership, content, expiry and relay credentials", async (t) => {
  const f = await fixture(t);
  let r = await f.request("/v1/servers", "POST", entry);
  assert.equal(r.status, 201);
  const s = await r.json();
  assert.equal((await f.request("/v1/servers")).status, 200);
  assert.equal(
    (await f.request("/v1/servers/" + s.id, "DELETE", undefined, identity()))
      .status,
    403,
  );
  r = await f.request("/v1/relay-credentials", "POST", { serverId: s.id });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).credential.length, 28);
  f.advance(61000);
  assert.deepEqual((await (await f.request("/v1/servers")).json()).servers, []);
});
test("reject replay, bad signature, endpoint reflection and missing notice", async (t) => {
  const f = await fixture(t);
  const body = JSON.stringify(entry),
    headers = {
      ...signedHeaders(f.keys, "POST", "/v1/servers", body),
      "x-bfe-notice": "2026-10-11",
    };
  assert.equal(
    (await fetch(f.base + "/v1/servers", { method: "POST", body, headers }))
      .status,
    201,
  );
  assert.equal(
    (await fetch(f.base + "/v1/servers", { method: "POST", body, headers }))
      .status,
    401,
  );
  assert.equal(
    (
      await f.request("/v1/servers", "POST", {
        ...entry,
        endpoints: [{ address: "8.8.8.8", port: 1234, transport: "udp" }],
      })
    ).status,
    400,
  );
  assert.equal((await fetch(f.base + "/v1/servers")).status, 428);
  assert.equal(
    (
      await f.request("/v1/servers", "POST", entry, f.keys, {
        "x-bfe-signature": "x".repeat(88),
      })
    ).status,
    401,
  );
});
test("relay-only hides endpoints, optional location defaults off, signed ban feed", async (t) => {
  const f = await fixture(t);
  const r = await f.request("/v1/servers", "POST", {
    ...entry,
    relayPolicy: "always",
    endpoints: [{ address: "8.8.8.8" }],
  });
  assert.equal(r.status, 201);
  const s = await r.json();
  assert.deepEqual(s.endpoints, []);
  assert.equal(s.location, null);
  const bans = await (await f.request("/v1/bans")).json();
  assert.ok(bans.signature);
  assert.deepEqual(bans.payload.bans, []);
});
test("untrusted forwarding headers cannot forge caller address", async (t) => {
  const f = await fixture(t);
  const r = await f.request("/v1/whoami", "GET", undefined, f.keys, {
    "x-real-ip": "8.8.8.8",
    "x-forwarded-for": "8.8.8.8",
  });
  assert.equal((await r.json()).address, "127.0.0.1");
});

test('signaling tickets are single-use and offers route only to listed servers', {timeout:5000}, async t => {
 const {WebSocket}=await import('ws'); const f=await fixture(t);
 const registration=await(await f.request('/v1/servers','POST',entry)).json();
 async function connect(keys){const {ticket}=await(await f.request('/v1/signal-ticket','POST',{},keys)).json();const url=f.base.replace('http:','ws:')+'/v1/signal?ticket='+ticket;const ws=new WebSocket(url);t.after(()=>ws.terminate());await new Promise((r,j)=>{ws.once('open',r);ws.once('error',j);});return{ws,url};}
 const host=await connect(f.keys),client=await connect(identity());
 const incoming=new Promise(r=>host.ws.once('message',data=>r(JSON.parse(data))));
 client.ws.send(JSON.stringify({to:registration.id,type:'offer',payload:'{"sdp":"test"}'}));
 const offer=await incoming;assert.equal(offer.type,'offer');assert.match(offer.from,/^[a-f0-9]{64}$/);
 const response=new Promise(r=>client.ws.once('message',data=>r(JSON.parse(data))));host.ws.send(JSON.stringify({to:offer.from,type:'answer',payload:'{"sdp":"answer"}'}));assert.equal((await response).from,registration.id);
 const duplicate=new WebSocket(host.url);await new Promise(r=>duplicate.once('error',r));assert.equal(duplicate.readyState,WebSocket.CLOSED);
});

test('registered host admits 32 relay peers with separate allocation quotas', {timeout:10000}, async t => {
  const {WebSocket}=await import('ws');const f=await fixture(t);
  const registration=await(await f.request('/v1/servers','POST',entry)).json();
  async function connect(keys){const r=await f.request('/v1/signal-ticket','POST',{},keys);assert.equal(r.status,200);const {ticket}=await r.json();const ws=new WebSocket(f.base.replace('http:','ws:')+'/v1/signal?ticket='+ticket);t.after(()=>ws.terminate());await new Promise((r,j)=>{ws.once('open',r);ws.once('error',j);});return ws;}
  const host=await connect(f.keys),usernames=new Set();
  assert.equal((await f.request('/v1/relay-credentials','POST',{serverId:registration.id,peerId:'a'.repeat(64)})).status,403);
  for(let i=0;i<32;i++) {
    const client=await connect(identity());const offer=new Promise(r=>host.once('message',raw=>r(JSON.parse(raw))));
    client.send(JSON.stringify({to:registration.id,type:'offer',payload:'{}'}));const {from}=await offer;
    const response=await f.request('/v1/relay-credentials','POST',{serverId:registration.id,peerId:from});assert.equal(response.status,200);
    usernames.add((await response.json()).username);
  }
  assert.equal(usernames.size,32);
  const outsider=identity();assert.equal((await f.request('/v1/relay-credentials','POST',{serverId:registration.id,peerId:'a'.repeat(64)},outsider)).status,403);
});
