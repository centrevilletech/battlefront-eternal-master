// Host-only moderation. This command never opens an HTTP administration port.
import { DatabaseSync } from "node:sqlite";
import { resolve } from "node:path";
const db = new DatabaseSync(
  resolve(process.env.DATA_DIR ?? "data", "master.sqlite"),
);
const [command, id, ...rest] = process.argv.slice(2);
try {
  if (command === "reports")
    console.log(
      JSON.stringify(
        db
          .prepare("SELECT * FROM reports ORDER BY created DESC LIMIT 100")
          .all(),
        null,
        2,
      ),
    );
  else if (command === "ban") {
    if (!/^[a-f0-9]{64}$/.test(id)) throw Error("invalid player key ID");
    const hours = Number(rest.shift());
    const reason = rest.join(" ");
    if (
      !Number.isFinite(hours) ||
      hours <= 0 ||
      hours > 8760 ||
      !reason ||
      reason.length > 1000
    )
      throw Error("usage: ban KEY_ID HOURS REASON");
    db.prepare(
      "INSERT OR REPLACE INTO bans(player,reason,expires) VALUES(?,?,?)",
    ).run(id, reason, Date.now() + hours * 3600000);
    console.log("Ban updated.");
  } else if (command === "unban") {
    if (!/^[a-f0-9]{64}$/.test(id)) throw Error("invalid player key ID");
    db.prepare("DELETE FROM bans WHERE player=?").run(id);
    console.log("Ban removed.");
  } else
    throw Error("Commands: reports | ban KEY_ID HOURS REASON | unban KEY_ID");
} finally {
  db.close();
}
