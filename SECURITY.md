# Sentinel Shield security model

## Reporting a vulnerability

Please report security issues privately to the maintainers, not in public issues. Include the version, a description, reproduction steps and the impact. We aim to acknowledge reports within 3 working days.

## What this plugin defends against (Phase 1)

| Threat | Mitigation |
| --- | --- |
| A known-bad IP or range keeps hitting the site | Manual block rules (IPv4, IPv6, CIDR) checked on every request while plugins load. |
| Repeat offenders | Progressive lockouts escalate within a configurable window (default 15 min → 1 h → 24 h → permanent). Later modules (login, 404, WAF) feed this engine. |
| IP spoofing via `X-Forwarded-For` / `CF-Connecting-IP` | Headers are ignored unless `REMOTE_ADDR` is inside a trusted proxy range. Multi-hop headers are walked right to left and the first untrusted hop is used, so values an attacker prepends are ignored. Malformed chains fall back to `REMOTE_ADDR`. |
| Admin lockout | Admin IP auto-allowlisted on activation and every settings save; rules covering the admin's IP are refused in the UI and CSV import; a warning shows if the admin's IP matches any block rule; emergency constant; WP-CLI unblock; emailed single-use unlock links; server wp-cron and WP-CLI are never blocked. |
| CSRF / privilege escalation in admin | Every admin action checks `manage_options` (or `manage_network_options` on multisite) and a nonce. The unlock form, which serves logged-out blocked visitors, uses an IP-bound hourly HMAC instead of a nonce, plus a honeypot and a per-IP rate limit. |
| SQL injection | All queries use `$wpdb->prepare()` with `%i` for identifiers. Binary IPs are passed as hex and converted with `UNHEX()`. |
| Unlock link abuse | Tokens are 256-bit random values; only SHA-256 hashes are stored; they expire (default 30 min) and are consumed atomically. Responses never reveal whether an email address has an account. |
| CSV formula injection | Exported cells beginning with `= + - @` are prefixed with `'`. |

## Trust boundaries and assumptions

* `REMOTE_ADDR` is set correctly by the web server. If PHP sits behind a reverse proxy on the same host, every request appears to come from `127.0.0.1` until a trusted proxy is configured. The IP Detection tab warns about this.
* The trusted proxy list is accurate. Trusting too much (for example `0.0.0.0/0`) lets anyone choose their IP. The load balancer preset trusts private ranges when its list is empty; do not use it if untrusted hosts can reach the server from a private network.
* The database and object cache are trusted.
* Administrators are trusted. Anyone with `manage_options` can disable the plugin.

## Known limitations (Phase 1)

* **Runs as a normal plugin.** The gate runs while plugins load, after WordPress core and must-use plugins. The `auto_prepend_file` firewall arrives in Phase 6.
* **Deferred unlock requests.** When a blocked visitor submits the unlock form, the block is deferred to `init` so `wp_mail()` can run. Other plugins load for that one request. A fail-closed fallback at `init` priority 1 sends the block page if the unlock handler does not.
* **No per-request rate limiting yet.** A blocked IP still costs one PHP bootstrap per request. Use server-level or CDN rate limiting for volumetric attacks.
* **Shared and rotating IPs.** Blocking a CGNAT or corporate IP can affect innocent users. IPv6 attackers can rotate within a /64; block the /64 or /48 when needed.
* **Cache staleness.** Without a persistent object cache, compiled rule sets live in site transients. Changes made through the plugin flush the cache immediately. Direct database edits are picked up within one hour, or at the next rule expiry, or after "Clear rule cache".
* **Event log de-duplication** needs a persistent object cache. Without one, a flood of blocked requests writes one event row per request; hourly pruning bounds growth.
* **Email delivery** is required for unlock links. Test it from Tools & Testing.
* **404 block response** hides the unlock form; use WP-CLI or the constant instead.

## Data stored

Tables use the network prefix (`{base_prefix}sentinel_*`): IP rules, events (IP, URI, user agent, reason), offenses and hashed unlock tokens. Events are pruned after the retention period (default 30 days). Settings are site options. Everything is removed on uninstall only when "Delete all data on uninstall" is enabled.
