#!/bin/sh
# Runs build/test_client against HIM's mock server on a spare port.
# MOCK is the mock-server binary (cargo build -p hotline-im --features mock-server
# --bin mock-server, in github.com/tagban/him).
set -e
cd "$(dirname "$0")/.."
MOCK=${MOCK:-../him/target/debug/mock-server}
PORT=${PORT:-15700}
if [ ! -x "$MOCK" ]; then
	echo "no mock server at $MOCK (set MOCK=...)" >&2
	exit 2
fi
rm -rf "${TMPDIR:-/tmp}/purple-hotline-test"
"$MOCK" "$PORT" > build/mock.log 2>&1 &
MOCK_PID=$!
# The tracker's files, served the way tracker.bigredh.com serves them.
TRACKER_PORT=$((PORT + 10))
python3 -m http.server "$TRACKER_PORT" --bind 127.0.0.1 --directory tests/fixtures > build/tracker.log 2>&1 &
TRACKER_PID=$!
trap 'kill $MOCK_PID $TRACKER_PID 2>/dev/null' EXIT
sleep 1
build/test_client "$PWD" "$PORT" "$TRACKER_PORT"
