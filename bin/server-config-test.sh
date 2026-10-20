#!/usr/bin/env bash
# Live web server test of the generated blocklist files: nginx and Apache
# load them, enforce them (blocked address refused, an allowlisted address
# inside a blocked range let through, others let through) and stop enforcing
# them after the policy is emptied and the server reloads.
#
# Usage: bin/server-config-test.sh <wordpress-path>
#   NGINX_BIN=/usr/sbin/nginx APACHE_BIN=/usr/sbin/apache2 APACHE_MODULES=/usr/lib/apache2/modules
#   (each server is skipped when its binary is missing; SKIP_NGINX=1 / SKIP_APACHE=1)
#
# Starts its own servers on 127.0.0.1:18081 (nginx) and :18082 (Apache) with
# configurations written to a temporary folder; nothing system-wide changes.
# The test configurations take the visitor address from X-Forwarded-For
# (realip / remoteip from 127.0.0.1), as a site behind a proxy would.
# DESTRUCTIVE: changes settings and rules. Use a throwaway site only.
set -euo pipefail

[ $# -ge 1 ] || { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
WP=(wp --path="$1")
NGINX_BIN=${NGINX_BIN:-$(command -v nginx || echo /usr/sbin/nginx)}
APACHE_BIN=${APACHE_BIN:-$(command -v apache2 || command -v httpd || echo /usr/sbin/apache2)}
APACHE_MODULES=${APACHE_MODULES:-/usr/lib/apache2/modules}
T=$(mktemp -d)
PIDS=()
cleanup() {
	[ -f "$T/nginx/nginx.pid" ] && kill "$(cat "$T/nginx/nginx.pid")" 2>/dev/null || true
	[ -f "$T/apache/httpd.pid" ] && kill "$(cat "$T/apache/httpd.pid")" 2>/dev/null || true
	rm -rf "$T"
}
trap cleanup EXIT
FAILED=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; FAILED=1; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $2" "http://127.0.0.1:$1/index.html"; }
# What a failed nginx step looked like: the include, the reload's own errors, nginx -t, the log.
nginx_diag() {
	echo "    --- $DATA/nginx-deny.conf:" >&2; ls -la "$DATA/nginx-deny.conf" >&2 2>&1 || true; head -5 "$DATA/nginx-deny.conf" >&2 2>&1 || true
	echo "    --- reload: ${RELOAD_ERR:-}" >&2
	echo "    --- answer for 203.0.113.8: $(code 18081 203.0.113.8); master $(cat "$T/nginx/nginx.pid" 2>/dev/null) alive: $(kill -0 "$(cat "$T/nginx/nginx.pid" 2>/dev/null)" 2>/dev/null && echo yes || echo no)" >&2
	"$NGINX_BIN" -t -p "$T/nginx" -c "$T/nginx/nginx.conf" >&2 2>&1 || true
	tail -n 12 "$T/nginx/error.log" >&2 2>/dev/null || true
	"${WP[@]}" sentinel early-gate status >&2 2>&1 || true
}
# A graceful reload is complete once the old workers are gone: until then an
# old worker can still take a connection and answer with the old rules.
workers_gone() { # pids...
	for i in $(seq 1 100); do
		local alive=0
		for p in "$@"; do kill -0 "$p" 2>/dev/null && alive=1; done
		[ $alive = 0 ] && return 0
		sleep 0.1
	done
	return 1
}
# The same answer ten times in a row (a few seconds at most).
settled() { # port ip expected
	local streak=0
	for i in $(seq 1 100); do
		if [ "$(code "$1" "$2")" = "$3" ]; then streak=$((streak + 1)); [ $streak -ge 10 ] && return 0; else streak=0; sleep 0.1; fi
	done
	return 1
}
port_free() { [ "$(code "$1" 198.51.100.1)" = 000 ] || { echo "Port $1 is already in use (a server left over from an earlier run?)" >&2; exit 1; }; }

echo "Server configuration test"
"${WP[@]}" sentinel test-mode off >/dev/null
"${WP[@]}" sentinel settings-set firewall.server_files 1 >/dev/null
"${WP[@]}" sentinel block 203.0.113.0/24 --reason=server-config-test >/dev/null
"${WP[@]}" sentinel allow 203.0.113.7 --reason=server-config-test >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null
DATA=$("${WP[@]}" eval 'echo SentinelShield\Support\DataDir::path();')
grep -q 'deny 203.0.113.0/30;' "$DATA/nginx-deny.conf" && ! grep -q '203.0.113.7' "$DATA/nginx-deny.conf" \
	&& pass "the allowlisted 203.0.113.7 is carved out of the blocked /24" || fail "unexpected nginx file: $(grep -c deny "$DATA/nginx-deny.conf") lines"
mkdir -p "$T/www" "$T/nginx" "$T/apache"
echo ok > "$T/www/index.html"

check_enforcing() { # port name
	[ "$(code "$1" 203.0.113.8)" = 403 ] && pass "$2: a blocked address is refused (403)" || fail "$2: 203.0.113.8 was not refused"
	[ "$(code "$1" 203.0.113.7)" = 200 ] && pass "$2: the allowlisted address inside the blocked range gets through" || fail "$2: 203.0.113.7 was refused"
	[ "$(code "$1" 198.51.100.1)" = 200 ] && pass "$2: other addresses get through" || fail "$2: 198.51.100.1 was refused"
}

empty_policy() {
	"${WP[@]}" sentinel unblock 203.0.113.9 --include-ranges >/dev/null
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
}

restore_policy() {
	"${WP[@]}" sentinel block 203.0.113.0/24 --reason=server-config-test >/dev/null
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
}

if [ "${SKIP_NGINX:-0}" != 1 ] && [ -x "$NGINX_BIN" ]; then
	echo "nginx ($("$NGINX_BIN" -v 2>&1 | sed 's/.*version: //'))"
	mkdir -p "$T/nginx/logs"
	port_free 18081
	cat > "$T/nginx/nginx.conf" <<EOF
pid $T/nginx/nginx.pid;
error_log $T/nginx/error.log notice;
events { worker_connections 64; }
http {
	access_log off;
	client_body_temp_path $T/nginx/body; proxy_temp_path $T/nginx/proxy; fastcgi_temp_path $T/nginx/fcgi;
	uwsgi_temp_path $T/nginx/uwsgi; scgi_temp_path $T/nginx/scgi;
	server {
		listen 127.0.0.1:18081;
		root $T/www;
		set_real_ip_from 127.0.0.1;
		real_ip_header X-Forwarded-For;
		include $DATA/nginx-deny.conf;
	}
}
EOF
	"$NGINX_BIN" -t -p "$T/nginx" -c "$T/nginx/nginx.conf" >/dev/null 2>&1 && pass "nginx -t accepts the generated file" || { "$NGINX_BIN" -t -p "$T/nginx" -c "$T/nginx/nginx.conf"; fail "nginx rejects the generated file"; }
	"$NGINX_BIN" -p "$T/nginx" -c "$T/nginx/nginx.conf"
	for i in $(seq 1 50); do [ "$(code 18081 198.51.100.1)" != 000 ] && break; sleep 0.1; done
	check_enforcing 18081 nginx
	empty_policy
	"$NGINX_BIN" -t -p "$T/nginx" -c "$T/nginx/nginx.conf" >/dev/null 2>&1 && pass "nginx -t accepts the emptied file" || fail "nginx rejects the emptied file"
	OLD_WORKERS=$(pgrep -P "$(cat "$T/nginx/nginx.pid")" || true)
	RELOAD_ERR=$("$NGINX_BIN" -s reload -p "$T/nginx" -c "$T/nginx/nginx.conf" 2>&1 | grep -v 'could not open error log' || true)
	# shellcheck disable=SC2086 # One pid per word.
	workers_gone $OLD_WORKERS || echo "    (old nginx workers still running after 10 s)" >&2
	settled 18081 203.0.113.8 200 && pass "nginx: after unblocking and a reload, the address gets through" || { fail "nginx still refuses 203.0.113.8 after reload"; nginx_diag; }
	"${WP[@]}" sentinel settings-set firewall.server_files 0 >/dev/null
	"$NGINX_BIN" -t -p "$T/nginx" -c "$T/nginx/nginx.conf" >/dev/null 2>&1 && pass "nginx: switching server files off leaves a loadable (empty) include" || { fail "nginx: the include broke when server files were switched off"; nginx_diag; }
	"${WP[@]}" sentinel settings-set firewall.server_files 1 >/dev/null
	restore_policy
	kill "$(cat "$T/nginx/nginx.pid")"; rm -f "$T/nginx/nginx.pid"
else
	echo "nginx: skipped (no binary at $NGINX_BIN)"
fi

if [ "${SKIP_APACHE:-0}" != 1 ] && [ -x "$APACHE_BIN" ] && [ -f "$APACHE_MODULES/mod_remoteip.so" ]; then
	echo "Apache ($("$APACHE_BIN" -v | sed -n 's/^Server version: //p'))"
	port_free 18082
	cat > "$T/apache/httpd.conf" <<EOF
ServerRoot $T/apache
ServerName localhost
Listen 127.0.0.1:18082
PidFile $T/apache/httpd.pid
ErrorLog $T/apache/error.log
Mutex file:$T/apache
LoadModule mpm_event_module $APACHE_MODULES/mod_mpm_event.so
LoadModule authz_core_module $APACHE_MODULES/mod_authz_core.so
LoadModule authz_host_module $APACHE_MODULES/mod_authz_host.so
LoadModule remoteip_module $APACHE_MODULES/mod_remoteip.so
<IfModule !mod_unixd.c>
LoadModule unixd_module $APACHE_MODULES/mod_unixd.so
</IfModule>
DocumentRoot $T/www
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 127.0.0.1
<Directory $T/www>
	Include $DATA/apache-deny.conf
</Directory>
EOF
	"$APACHE_BIN" -t -f "$T/apache/httpd.conf" >/dev/null 2>&1 && pass "apache -t accepts the generated file" || { "$APACHE_BIN" -t -f "$T/apache/httpd.conf"; fail "Apache rejects the generated file"; }
	"$APACHE_BIN" -f "$T/apache/httpd.conf" -k start
	for i in $(seq 1 50); do [ "$(code 18082 198.51.100.1)" != 000 ] && break; sleep 0.1; done
	check_enforcing 18082 Apache
	empty_policy
	"$APACHE_BIN" -t -f "$T/apache/httpd.conf" >/dev/null 2>&1 && pass "apache -t accepts the emptied file" || fail "Apache rejects the emptied file"
	"$APACHE_BIN" -f "$T/apache/httpd.conf" -k graceful
	settled 18082 203.0.113.8 200 && pass "Apache: after unblocking and a graceful restart, the address gets through" || fail "Apache still refuses 203.0.113.8 after reload"
	restore_policy
	"$APACHE_BIN" -f "$T/apache/httpd.conf" -k stop; sleep 0.5; rm -f "$T/apache/httpd.pid"
else
	echo "Apache: skipped (no binary at $APACHE_BIN or no modules in $APACHE_MODULES)"
fi

"${WP[@]}" eval 'global $wpdb; $r = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Repository\BlockRepository::class ); $wpdb->query( $wpdb->prepare( "DELETE FROM %i WHERE reason = %s", $r->table(), "server-config-test" ) );' >/dev/null
"${WP[@]}" sentinel flush-cache >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null
[ "$FAILED" = 0 ] && echo "Server configuration test passed." || { echo "Server configuration test FAILED."; exit 1; }
