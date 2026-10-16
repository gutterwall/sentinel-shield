# Nginx and web server notes

Phase 1 has no `.htaccess`-dependent features. These snippets cover what Phase 1 does depend on: correct client IPs, and keeping development files private. Later phases (PHP execution in uploads, sensitive files, WAF `auto_prepend_file`) will add their snippets here.

## 1. Client IP: choose one place to trust proxies

**Option A (recommended): let Sentinel Shield decide.** Leave `REMOTE_ADDR` as the real TCP peer and pick the Trusted Proxy preset in the plugin. Do not use `real_ip_header` in Nginx.

**Option B: let Nginx decide.** If Nginx already rewrites `REMOTE_ADDR` with the realip module, set the plugin's Trusted Proxy to **None**. Otherwise the IP is resolved twice.

```nginx
# Option B, Cloudflare in front of Nginx (http {} or server {} block)
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
```

Cloudflare publishes the current list at https://www.cloudflare.com/ips/. If you use Option B, keep it updated yourself; the plugin's weekly auto-update only applies to Option A.

## 2. Reverse proxy in front of PHP-FPM on the same host

If Nginx (or Varnish/Caddy) proxies to another web server, forward the client IP:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $host;
}
```

Then in the plugin choose **Custom**, header `X-Forwarded-For`, trusted IP `127.0.0.1`.

## 3. Keep plugin development files private

These files are harmless but there is no reason to serve them:

```nginx
location ~* ^/wp-content/plugins/sentinel-shield/(tests|vendor|docs|composer\.(json|lock)|phpunit\.xml\.dist|phpcs\.xml\.dist) {
    deny all;
    return 404;
}
```

Apache equivalent, in `wp-content/plugins/sentinel-shield/.htaccess`:

```apache
<FilesMatch "^(composer\.(json|lock)|phpunit\.xml\.dist|phpcs\.xml\.dist)$">
    Require all denied
</FilesMatch>
RedirectMatch 404 ^/wp-content/plugins/sentinel-shield/(tests|vendor|docs)/
```

## 4. System cron (optional)

The plugin's hourly housekeeping uses WP-Cron. Requests to `wp-cron.php` from the server's own IP are never blocked. For reliability on low-traffic sites:

```cron
*/5 * * * * cd /var/www/html && wp cron event run --due-now --quiet
```
