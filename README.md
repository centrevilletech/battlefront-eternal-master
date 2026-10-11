# Battlefront Eternal master

GPL-3.0-only directory and signaling service. Runs under Node 22.13+ or Docker.
No game data, match simulation, mandatory third-party identity, or software updates
come from this service. The protocol is pre-release; clients must explicitly
acknowledge the current `/v1/info` notice before online requests.

Run `npm ci && npm test`, then `npm start`. Default listener: port 8080.
Persist `DATA_DIR` (default `data`) for the signing key, reports and ban database.
Docker deployment uses `docker-compose.portainer.production.yml` behind Aldine's
Nginx Proxy Manager on external network `proxy-web`. Set `APP_IMAGE`, a shared
`TURN_SECRET`, and the exact proxy container address in `TRUSTED_PROXIES`.

API: `/healthz`, `/v1/info`, `/v1/whoami`, `/v1/servers`, `/v1/servers/:id`,
`/v1/relay-credentials`, `/v1/signal-ticket`, `/v1/signal`, `/v1/reports`, `/v1/bans`.
Mutation signatures are Ed25519 over method, request target, Unix seconds,
128-bit nonce, and SHA-256 of the exact body, separated by newlines. See
`src/auth.js` for the interoperable implementation. Requests expire after 60
seconds; replay nonces stay in memory for 125 seconds. Local identities require
no Steam or account service. Server IDs derive from their public keys.

Signal tickets expire after 30 seconds and allow one upgrade. Signaling payloads
are untrusted; clients must verify identity and bind transport fingerprints.
Only source-address endpoints are accepted until signed reachability probes are
implemented. They remain `verified:false`; do not label them reachable from this
response. Relay-only listings omit endpoints. Heartbeats expire after 60 seconds.
Reports expire after 30 days. Ban policy belongs to the game server; the master
does not deny relay admission merely because a player appears in the ban feed.

Outstanding release gates: signed reachability probes, moderation administration,
sponsor approval, operational privacy review, and complete game/client integration.
The service's tests do not establish a finished multiplayer game.
