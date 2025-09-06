#!/usr/bin/env bash
set -euo pipefail

IP=${1:-192.168.4.1}
PORT=${2:-8081}
ITER=${3:-50}
CLIENT=${CLIENT_BIN:-./host_test/mlkem_client}

echo "Running $ITER handshakes against $IP:$PORT using $CLIENT"
ok=0; fail=0
for i in $(seq 1 "$ITER"); do
  out="$($CLIENT "$IP" "$PORT" 2>&1 || true)"
  if grep -q "shared secret MATCH" <<<"$out"; then
    ((ok++))
  else
    ((fail++))
    echo "---- FAIL #$i ----"
    echo "$out"
  fi
  sleep 0.05
done

echo "Done. OK=$ok FAIL=$fail"
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
