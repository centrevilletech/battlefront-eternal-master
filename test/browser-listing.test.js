import { test } from "node:test";
import assert from "node:assert/strict";
import { identity, signedHeaders } from "../src/auth.js";
import { battleQuery, createMaster } from "../src/server.js";

const entry = {
  name: "Planet Lightwave - Pro Duals", protocol: 3, simulation: "bfe-sim-25", content: "c",
  rotation: ["swbf1/bes2:rep:conquest", "swbf1/bes2:imp:conquest"], players: 2, maxPlayers: 64,
  relayPolicy: "never", fingerprint: "sha-256 " + Array(32).fill("AB").join(":"),
  endpoints: [{ port: 18452, transport: "udp" }],
  description: "Cloud City only. No bots; teams assigned.",
  sponsor: { name: "Alabama Lightwave", url: "https://alabamalightwave.com/", logo: "https://alabamalightwave.com/images/al-logo-white.png" },
  location: "Alabama, US",
  query: "?map=bes2&side=rep&ai=off&seed=1&match=" + "a".repeat(32),
  battle: { map: "bes2", mapName: "BESPIN: CLOUD CITY", side: "rep", era: "cw", mode: "conquest" },
  bots: false, autoAssignTeams: true, uptime: 3600,
};

// A master behind a trusted proxy, so each request can come from the
// address its x-real-ip names (a server's IPv4 and IPv6 heartbeats).
async function fixture(t) {
  let now = Date.now();
  const app = createMaster({ now: () => now, trustedProxies: ["127.0.0.1"], signingKey: identity().privateKey });
  await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
  t.after(() => app.close());
  const base = `http://127.0.0.1:${app.server.address().port}`, keys = identity();
  const request = (path, method, value, from) => {
    const body = value === undefined ? "" : JSON.stringify(value);
    return fetch(base + path, { method, headers: { "x-bfe-notice": "2026-10-11", "x-real-ip": from, ...signedHeaders(keys, method, path, body, now) }, body: body || undefined });
  };
  return { request, advance: (ms) => (now += ms) };
}

test("the listing carries what the server browser shows, and leaves out what does not check out", async (t) => {
  const f = await fixture(t);
  const r = await f.request("/v1/servers", "POST", entry, "8.8.8.8");
  assert.equal(r.status, 201);
  const s = await r.json();
  for (const key of ["description", "sponsor", "location", "query", "battle", "bots", "autoAssignTeams", "uptime"]) assert.deepEqual(s[key], entry[key], key);
  const odd = await (await f.request("/v1/servers/" + s.id, "PUT", { ...entry, description: "bad\u0007", sponsor: { name: "S", url: "http://insecure.example/", logo: "javascript:alert(1)" },
    query: "?map=bes2&side=rep&noreload=1", battle: { map: "../etc" }, bots: "yes", uptime: -1 }, "8.8.8.8")).json();
  assert.deepEqual([odd.description, odd.sponsor, odd.query, odd.battle, odd.bots, odd.uptime], [null, { name: "S", url: null, logo: null }, null, null, null, null], "dropped, never refused");
  assert.equal(odd.name, entry.name, "the server stays listed");
});

test("a page's battle query keeps to the battle's own keys", () => {
  assert.equal(battleQuery("?map=bes2&side=imp&ai=off&seed=1&match=" + "f".repeat(32)), "?map=bes2&side=imp&ai=off&seed=1&match=" + "f".repeat(32));
  for (const bad of ["?map=bes2&debug=1", "?side=rep", "?map=bes2&ai=enhanced", "?map=bes2&map=nab2", "map=bes2", "?map=<x>"]) assert.throws(() => battleQuery(bad), /invalid query/, bad);
});

test("a direct server is listed at the address of each family its heartbeats come from, while fresh", async (t) => {
  const f = await fixture(t);
  const s = await (await f.request("/v1/servers", "POST", entry, "8.8.8.8")).json();
  assert.deepEqual(s.endpoints, [{ address: "8.8.8.8", port: 18452, transport: "udp", verified: false }]);
  f.advance(20000);
  const both = await (await f.request("/v1/servers/" + s.id, "PUT", entry, "2001:4860:4860::8888")).json();
  assert.deepEqual(both.endpoints.map((e) => e.address).sort(), ["2001:4860:4860:0:0:0:0:8888", "8.8.8.8"].sort());
  // IPv4 stops (the host lost it): its address goes after 90 seconds.
  for (let i = 0; i < 5; i++) { f.advance(20000); await f.request("/v1/servers/" + s.id, "PUT", entry, "2001:4860:4860::8888"); }
  const listed = (await (await f.request("/v1/servers", "GET", undefined, "8.8.4.4")).json()).servers[0];
  assert.deepEqual(listed.endpoints.map((e) => e.address), ["2001:4860:4860:0:0:0:0:8888"]);
  const relayed = await (await f.request("/v1/servers/" + s.id, "PUT", { ...entry, relayPolicy: "auto", endpoints: [] }, "8.8.8.8")).json();
  assert.deepEqual(relayed.endpoints, [], "a server that lists no endpoint has none");
  assert.equal((await f.request("/v1/servers/" + s.id, "PUT", { ...entry, endpoints: [{ address: "1.1.1.1", port: 18452, transport: "udp" }] }, "8.8.8.8")).status, 400, "another address still needs proof");
});
