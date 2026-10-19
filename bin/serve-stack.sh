#!/usr/bin/env bash
# Serves a WordPress site through a production-style stack for the HTTP tests:
# nginx or Apache in front of PHP-FPM, with the early firewall prepended the
# way the Server & CDN tab tells administrators to (fastcgi_param PHP_VALUE
# for nginx, the PHP-FPM pool for Apache).
#
# Usage: bin/serve-stack.sh <nginx|apache> <wordpress-path> <port> [https-port]
#   Environment: NGINX_BIN, APACHE_BIN, APACHE_MODULES, FPM_BIN (binaries), PHP_INI (php.ini
#   to use, default: the CLI's), FPM_CHILDREN (default 12), GATE_CONFIG (path of
#   gate.json, default: the plugin's own), PLUGIN (plugin folder, default: this
#   checkout).
#   With https-port, nginx also terminates TLS there (self-signed certificate)
#   and passes X-Forwarded-Proto / X-Forwarded-For to the same site.
#
# Runs in the foreground until killed; writes logs and configs to
# $STACK_DIR (default: a temporary folder) and prints "ready" when serving.
set -euo pipefail

[ $# -ge 3 ] || { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
KIND=$1
ROOT=$(cd "$2" && pwd)
PORT=$3
HTTPS_PORT=${4:-}
PLUGIN=${PLUGIN:-$(cd "$(dirname "$0")/.." && pwd)}
NGINX_BIN=${NGINX_BIN:-$(command -v nginx || echo /usr/sbin/nginx)}
APACHE_BIN=${APACHE_BIN:-$(command -v apache2 || echo /usr/sbin/apache2)}
APACHE_MODULES=${APACHE_MODULES:-/usr/lib/apache2/modules}
FPM_BIN=${FPM_BIN:-$(command -v php-fpm8.3 || command -v php-fpm || echo /usr/sbin/php-fpm8.3)}
PHP_INI=${PHP_INI:-$(php -r 'echo php_ini_loaded_file();')}
CHILDREN=${FPM_CHILDREN:-12}
D=${STACK_DIR:-$(mktemp -d)}
mkdir -p "$D"
GATE=$PLUGIN/early-gate.php
GATE_CONFIG=${GATE_CONFIG:-$(wp --path="$ROOT" eval 'echo SentinelShield\Support\DataDir::path();' 2>/dev/null)/gate.json}
SOCK=$D/fpm.sock

cat > "$D/fpm.conf" <<EOF
[global]
error_log = $D/fpm-error.log
pid = $D/fpm.pid
daemonize = no
[www]
listen = $SOCK
pm = static
pm.max_children = $CHILDREN
clear_env = no
catch_workers_output = yes
php_admin_value[error_log] = $D/php-error.log
php_admin_flag[log_errors] = on
EOF
if [ "$KIND" = apache ]; then
	# mod_proxy_fcgi cannot set PHP_VALUE per request: prepend in the pool.
	cat >> "$D/fpm.conf" <<EOF
php_admin_value[auto_prepend_file] = $GATE
env[SENTINEL_SHIELD_GATE_CONFIG] = $GATE_CONFIG
EOF
fi
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

PHP_INI_SCAN_DIR=${PHP_INI_SCAN_DIR:-$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')} "$FPM_BIN" -F -y "$D/fpm.conf" -c "$PHP_INI" &
PIDS+=($!)
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { cat "$D/fpm-error.log"; echo "PHP-FPM did not start" >&2; exit 1; }

if [ "$KIND" = nginx ]; then
	TLS=''
	if [ -n "$HTTPS_PORT" ]; then
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
			-keyout "$D/key.pem" -out "$D/cert.pem" >/dev/null 2>&1
		# TLS terminates here and is passed on as a trusted proxy would (X-Forwarded-*).
		TLS="server {
		listen 127.0.0.1:$HTTPS_PORT ssl;
		ssl_certificate $D/cert.pem;
		ssl_certificate_key $D/key.pem;
		location / {
			proxy_pass http://127.0.0.1:$PORT;
			proxy_set_header Host \$http_host;
			proxy_set_header X-Forwarded-Proto https;
			proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		}
	}"
	fi
	cat > "$D/nginx.conf" <<EOF
pid $D/nginx.pid;
error_log $D/nginx-error.log;
daemon off;
worker_processes 2;
events { worker_connections 256; }
http {
	access_log off;
	client_body_temp_path $D/body; proxy_temp_path $D/proxy; fastcgi_temp_path $D/fcgi; uwsgi_temp_path $D/uwsgi; scgi_temp_path $D/scgi;
	client_max_body_size 20m;
	types { text/html html; text/css css; application/javascript js; image/png png; image/svg+xml svg; }
	server {
		listen 127.0.0.1:$PORT;
		root $ROOT;
		index index.php;
		location / { try_files \$uri \$uri/ /index.php?\$args; }
		location ~ \.php\$ {
			try_files \$uri =404;
			fastcgi_pass unix:$SOCK;
			fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
			fastcgi_param QUERY_STRING \$query_string; fastcgi_param REQUEST_METHOD \$request_method;
			fastcgi_param CONTENT_TYPE \$content_type; fastcgi_param CONTENT_LENGTH \$content_length;
			fastcgi_param SCRIPT_NAME \$fastcgi_script_name; fastcgi_param REQUEST_URI \$request_uri;
			fastcgi_param DOCUMENT_URI \$document_uri; fastcgi_param DOCUMENT_ROOT \$document_root;
			fastcgi_param SERVER_PROTOCOL \$server_protocol; fastcgi_param REMOTE_ADDR \$remote_addr;
			fastcgi_param REMOTE_PORT \$remote_port; fastcgi_param SERVER_ADDR \$server_addr;
			fastcgi_param SERVER_PORT \$server_port; fastcgi_param SERVER_NAME \$server_name;
			fastcgi_param HTTPS \$https if_not_empty;
			# As shown on the Server & CDN tab:
			fastcgi_param PHP_VALUE "auto_prepend_file=$GATE";
			fastcgi_param SENTINEL_SHIELD_GATE_CONFIG "$GATE_CONFIG";
		}
	}
	$TLS
}
EOF
	mkdir -p "$D/body"
	"$NGINX_BIN" -t -p "$D" -c "$D/nginx.conf" 2>"$D/nginx-test.log" || { cat "$D/nginx-test.log"; exit 1; }
	"$NGINX_BIN" -p "$D" -c "$D/nginx.conf" &
	PIDS+=($!)
elif [ "$KIND" = apache ]; then
	cat > "$D/httpd.conf" <<EOF
ServerRoot $D
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $D/httpd.pid
ErrorLog $D/apache-error.log
Mutex file:$D
LoadModule mpm_event_module $APACHE_MODULES/mod_mpm_event.so
LoadModule authz_core_module $APACHE_MODULES/mod_authz_core.so
LoadModule authz_host_module $APACHE_MODULES/mod_authz_host.so
<IfModule !mod_unixd.c>
LoadModule unixd_module $APACHE_MODULES/mod_unixd.so
</IfModule>
LoadModule dir_module $APACHE_MODULES/mod_dir.so
LoadModule mime_module $APACHE_MODULES/mod_mime.so
LoadModule rewrite_module $APACHE_MODULES/mod_rewrite.so
LoadModule proxy_module $APACHE_MODULES/mod_proxy.so
LoadModule proxy_fcgi_module $APACHE_MODULES/mod_proxy_fcgi.so
LoadModule setenvif_module $APACHE_MODULES/mod_setenvif.so
TypesConfig /dev/null
DocumentRoot $ROOT
DirectoryIndex index.php
StartServers 2
ThreadsPerChild 25
<Directory $ROOT>
	AllowOverride All
	Require all granted
</Directory>
<FilesMatch "\.php\$">
	SetHandler "proxy:unix:$SOCK|fcgi://localhost"
</FilesMatch>
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=\$1
EOF
	# WordPress's own rewrite rules, for pretty links.
	[ -f "$ROOT/.htaccess" ] || printf '<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %%{REQUEST_FILENAME} !-f\nRewriteCond %%{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n' > "$ROOT/.htaccess"
	"$APACHE_BIN" -t -f "$D/httpd.conf" 2>"$D/apache-test.log" || { cat "$D/apache-test.log"; exit 1; }
	"$APACHE_BIN" -f "$D/httpd.conf" -DFOREGROUND &
	PIDS+=($!)
else
	echo "Unknown server: $KIND (nginx or apache)" >&2
	exit 2
fi

for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/wp-login.php" && break; sleep 0.2; done
echo "ready: $KIND + PHP-FPM ($CHILDREN workers) on http://127.0.0.1:$PORT${HTTPS_PORT:+ and https://127.0.0.1:$HTTPS_PORT}; logs in $D"
wait
