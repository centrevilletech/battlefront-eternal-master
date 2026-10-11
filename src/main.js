import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { identity } from "./auth.js";
import { createMaster } from "./server.js";
const data = resolve(process.env.DATA_DIR ?? "data");
mkdirSync(data, { recursive: true, mode: 0o700 });
const keyPath = resolve(data, "signing-key.pem");
if (!existsSync(keyPath))
  writeFileSync(keyPath, identity().privateKey, { mode: 0o600, flag: "wx" });
const app = createMaster({
  database: resolve(data, "master.sqlite"),
  signingKey: readFileSync(keyPath, "utf8"),
  turnSecret: process.env.TURN_SECRET,
  turnUrls: (process.env.TURN_URLS ?? "").split(",").filter(Boolean),
  trustedProxies: (process.env.TRUSTED_PROXIES ?? "")
    .split(",")
    .filter(Boolean),
  operator: process.env.OPERATOR,
  contact: process.env.CONTACT,
});
app.server.listen(
  Number(process.env.PORT ?? 8080),
  process.env.HOST ?? "0.0.0.0",
  () => console.log("Battlefront Eternal master listening"),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => app.close().then(() => process.exit(0)));
