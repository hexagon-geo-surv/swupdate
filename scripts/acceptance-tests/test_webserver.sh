#!/bin/sh
# SPDX-FileCopyrightText: 2026 Bastian Germann
# SPDX-License-Identifier: GPL-2.0-only
#
# Integration tests for the SWUpdate webserver.
#
# Usage: test_webserver.sh [path-to-swupdate] [port]

SWUPDATE="${1:-./swupdate}"
PORT="${2:-18080}"
BASE_URL="http://127.0.0.1:$PORT"
DOCROOT=
SWUPDATE_PID=
FAKE_SWU=
pass=0
fail=0

cleanup() {
	[ -n "$FAKE_SWU" ] && rm -f "$FAKE_SWU"
	if [ -n "$SWUPDATE_PID" ]; then
		pkill -TERM -P "$SWUPDATE_PID" 2>/dev/null || true
		kill "$SWUPDATE_PID" 2>/dev/null || true
		wait "$SWUPDATE_PID" 2>/dev/null || true
	fi
	[ -n "$DOCROOT" ] && rm -rf "$(dirname "$DOCROOT")"
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------
DOCROOT=$(mktemp -d)/doc
mkdir "$DOCROOT"
echo "hello webserver" > "$DOCROOT/index.html"
echo "body { color: red; }" > "$DOCROOT/style.css"
echo "canary" > "$(dirname "$DOCROOT")/passwd"

FAKE_SWU=$(mktemp --suffix=.swu)
echo "not a real swu" > "$FAKE_SWU"

"$SWUPDATE" -l 3 -w "-p $PORT -r $DOCROOT" >/dev/null 2>&1 &
SWUPDATE_PID=$!

# Wait up to 10 s for the server to start accepting connections
i=0
while ! curl -sf --max-time 1 "$BASE_URL/index.html" >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 10 ]; then
		echo "FAIL setup: webserver not ready after 10 s"
		exit 1
	fi
	sleep 1
done

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
assert_http() {
	desc="$1"
	expected="$2"
	shift 2
	actual=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$@")
	if [ "$actual" = "$expected" ]; then
		echo "PASS: $desc (HTTP $actual)"
		pass=$((pass + 1))
	else
		echo "FAIL: $desc (expected HTTP $expected, got HTTP $actual)"
		fail=$((fail + 1))
	fi
}

assert_http_in() {
	desc="$1"
	expected_pat="$2"
	shift 2
	actual=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$@")
	if echo "$actual" | grep -qE "^($expected_pat)$"; then
		echo "PASS: $desc (HTTP $actual)"
		pass=$((pass + 1))
	else
		echo "FAIL: $desc (expected HTTP in {$expected_pat}, got HTTP $actual)"
		fail=$((fail + 1))
	fi
}

assert_body() {
	desc="$1"
	pattern="$2"
	shift 2
	body=$(curl -s --max-time 5 "$@")
	if echo "$body" | grep -q "$pattern"; then
		echo "PASS: $desc"
		pass=$((pass + 1))
	else
		echo "FAIL: $desc (pattern '$pattern' not found in response)"
		fail=$((fail + 1))
	fi
}

# -----------------------------------------------------------------------
# Static file serving
# -----------------------------------------------------------------------
assert_http  "GET /index.html returns 200"         200 "$BASE_URL/index.html"
assert_http  "GET /style.css returns 200"          200 "$BASE_URL/style.css"
assert_http  "GET / returns 200"                   200 "$BASE_URL/"
assert_body  "GET /index.html body is correct"     "hello webserver" \
             "$BASE_URL/index.html"

# -----------------------------------------------------------------------
# 404 for unknown resources
# -----------------------------------------------------------------------
assert_http  "GET unknown file returns 404"        404 "$BASE_URL/no-such-file.txt"

# -----------------------------------------------------------------------
# Path traversal prevention
# -----------------------------------------------------------------------
# The canary file next to the docroot is never served, confirming the
# traversal is blocked. It must be a 40x error.
assert_http_in "Path traversal attempt is blocked" "40[0-6]" \
               --path-as-is "$BASE_URL/../passwd"

# -----------------------------------------------------------------------
# /restart endpoint
# -----------------------------------------------------------------------
# POST: ipc_postupdate may return ACK (HTTP 200/201) or fail (HTTP 500);
# both are valid HTTP responses.
assert_http_in "POST /restart returns valid HTTP response" "200|201|500" \
               -X POST "$BASE_URL/restart"

# -----------------------------------------------------------------------
# /upload endpoint
# -----------------------------------------------------------------------
# Multipart POST: the swupdate installer is running in the parent process,
# so ipc_inst_start_ext should succeed (HTTP 200).  If the installer is
# not yet ready the upload handler returns HTTP 500.
assert_http_in "POST /upload multipart returns valid HTTP response" "200|500" \
               -X POST -F "file=@$FAKE_SWU;filename=test.swu" \
               "$BASE_URL/upload"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "Results: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
