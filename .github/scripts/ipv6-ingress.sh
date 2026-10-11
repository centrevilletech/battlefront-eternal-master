#!/bin/bash
set -euo pipefail
# Preserve source addresses through Docker for the existing HTTPS proxy.
# No SSH, Tailscale, IPv4, or application routing changes.
name=bfe-proxy-ipv6
container=nginx-proxy-manager-app-1
public=2600:3c02::2000:34ff:fe00:7583
inside=fd42:bfe:443::2
if ! docker network inspect "$name" >/dev/null 2>&1; then
 docker network create --driver bridge --ipv6 --ipv4=false --subnet fd42:bfe:443::/64 "$name" >/dev/null
fi
if ! docker inspect "$container" --format '{{json .NetworkSettings.Networks}}' | python3 -c 'import json,sys;sys.exit(0 if "bfe-proxy-ipv6" in json.load(sys.stdin) else 1)'; then
 docker network connect --ip6 "$inside" "$name" "$container"
fi
add() { local table=$1 chain=$2; shift 2; ip6tables -w -t "$table" -C "$chain" "$@" 2>/dev/null || ip6tables -w -t "$table" -I "$chain" 1 "$@"; }
add filter DOCKER-USER -d "$inside" -p tcp -m multiport --dports 80,443 -m comment --comment bfe-ipv6-source -j ACCEPT
add filter DOCKER-USER -s "$inside" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment bfe-ipv6-source -j ACCEPT
for port in 80 443; do
 add nat PREROUTING -d "$public" -p tcp --dport "$port" -m comment --comment bfe-ipv6-source -j DNAT --to-destination "[$inside]:$port"
done
