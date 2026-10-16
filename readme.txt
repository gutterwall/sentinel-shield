=== Sentinel Shield ===
Contributors: sentinelshield
Tags: security, firewall, brute force, ip blocking, lockout
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-hosted firewall, IP blocklists, progressive lockouts and hardening. No paid cloud service required.

== Description ==

Sentinel Shield is a self-hosted security plugin. Everything runs on your server; optional external integrations are off by default.

**This release (0.1.0) contains the Phase 1 foundation:**

* Spoof-resistant client IP detection. Uses REMOTE_ADDR by default and reads forwarding headers only from trusted proxies. Presets: None, Cloudflare (ranges auto-updated weekly), load balancer with custom header, custom CIDR list. The settings page shows the detected IP and raw headers.
* IP allowlist and blocklist for single IPs, CIDR ranges and IPv6, with reason, source, created/expiry time and hit counts. CSV import/export.
* Progressive lockout engine (for example 15 min → 1 h → 24 h → permanent) used by upcoming modules.
* Lockout safety: the admin's IP is auto-allowlisted on activation and every settings save, a warning appears if your own IP matches a block rule, rules that would block your own IP are refused, `SENTINEL_SHIELD_DISABLE` emergency constant, `wp sentinel unblock <ip>`, emailed one-time unlock links, and wp-cron.php from the server plus all WP-CLI requests are never blocked.
* Test mode everywhere: global log-only mode with optional auto-expiry, per-module overrides, scope choice (all blocks or automatic only), a decision simulator, an IP resolution simulator, a lockout tester, a block page preview and a test unlock email.
* Security events log, dashboard and admin bar counter.
* Multisite: network-wide rules and settings; per-site overrides for the block page.
* WP-CLI: `wp sentinel status|check|resolve-ip|block|allow|unblock|remove|list|lockout|test-mode|settings-get|settings-set|settings-keys|settings-export|settings-import|cloudflare-update|flush-cache|prune|unlock-link|events`.

**Roadmap:** login protection and 2FA, 404 flood blocking, GeoIP login restriction, hardening toggles, WP-Cron monitor, WAF (auto_prepend_file), malware and integrity scanner, audit log, alerts and the full dashboard.

== Installation ==

1. Upload the `sentinel-shield` folder to `/wp-content/plugins/` (or install the zip).
2. Activate it (on multisite: Network Activate). The plugin starts in **test mode**; nothing is blocked yet and your IP is allowlisted.
3. Go to Sentinel Shield → Settings → IP Detection and confirm "Detected IP" matches your real public IP. If your site is behind Cloudflare or a load balancer, choose the matching preset.
4. Review Sentinel Shield → Events for "would block" entries.
5. Turn off test mode on Sentinel Shield → Tools & Testing.

Developers: run `composer install` for the test and coding-standards tools. The plugin itself has no runtime Composer dependencies in this release.

== Frequently Asked Questions ==

= I locked myself out. What now? =

Any one of these works:

* Add `define( 'SENTINEL_SHIELD_DISABLE', true );` to wp-config.php, log in, fix the rule, then remove the line.
* Run `wp sentinel unblock <your-ip> --allow-hours=24`.
* Use "Send unlock link" on the block page (403 mode only) with your administrator email address.

= Why does every visitor have the same IP? =

Your site is behind a proxy and Trusted Proxy is set to None. Pick the matching preset on the IP Detection tab and use the IP resolution simulator on the Tools page to check it.

= Does test mode protect anything? =

No. Test mode only records what would have been blocked. Use it to validate settings, then turn it off.

== Changelog ==

= 0.1.0 =
* Phase 1: core framework, client IP detection, IP rules, lockout engine, lockout safety, test mode tooling, events, WP-CLI.
