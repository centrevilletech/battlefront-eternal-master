#!/usr/bin/env bash
set -euo pipefail
: "${PORTAINER_URL:?}" "${PORTAINER_API_KEY:?}" "${PORTAINER_ENDPOINT_ID:?}" "${STACK_NAME:?}" "${APP_IMAGE:?}" "${TURN_SECRET:?}"
api() { curl --fail-with-body --silent --show-error --max-time 300 -H "X-API-Key: $PORTAINER_API_KEY" "$@"; }
base="${PORTAINER_URL%/}/api"
id="$(api "$base/stacks" | jq -r --arg n "$STACK_NAME" '[.[]|select(.Name==$n)]|first|.Id // empty')"
env_json="$(jq -n --arg image "$APP_IMAGE" --arg secret "$TURN_SECRET" --arg proxy "${TRUSTED_PROXIES:-}" '[{name:"APP_IMAGE",value:$image},{name:"TURN_SECRET",value:$secret},{name:"TRUSTED_PROXIES",value:$proxy}]')"
payload="$(jq -n --rawfile file docker-compose.portainer.production.yml --arg name "$STACK_NAME" --argjson env "$env_json" '{name:$name,stackFileContent:$file,env:$env,pullImage:true,prune:false}')"
if [ -z "$id" ]; then
 api -X POST "$base/stacks/create/standalone/string?endpointId=$PORTAINER_ENDPOINT_ID" -H 'Content-Type: application/json' --data "$payload" | jq '{Id,Name}'
else
 api -X PUT "$base/stacks/$id?endpointId=$PORTAINER_ENDPOINT_ID" -H 'Content-Type: application/json' --data "$payload" | jq '{Id,Name}'
fi
for i in $(seq 1 36); do
 state="$(api "$base/endpoints/$PORTAINER_ENDPOINT_ID/docker/containers/$STACK_NAME/json")"
 if jq -e --arg image "$APP_IMAGE" '.State.Health.Status=="healthy" and .Config.Image==$image' <<< "$state" >/dev/null; then echo 'Deployment healthy'; exit 0; fi
 sleep 5
done
echo 'Deployment did not become healthy' >&2
exit 1
