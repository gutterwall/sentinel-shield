=== Sentinel Shield ===
Contributors: gutterwall
Tags: security, firewall, two-factor, brute force, login
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.9.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-hosted firewall, brute-force protection, two-factor login with passkeys, IP blocklists, login location rules and malware lockdown.

== Description ==

Sentinel Shield is a self-hosted security plugin. It runs on your server, needs no account, and sends nothing about your visitors anywhere unless you set up an integration that does (see "External services" below). It starts in test mode, so you can check what it would block before it blocks anything.

**Firewall and IP rules**

* Spoof-resistant client IP detection: REMOTE_ADDR by default, forwarding headers only from trusted proxies (presets for Cloudflare, load balancers and custom ranges).
* Allowlist and blocklist for IPs and CIDR ranges (IPv4 and IPv6) with reasons, expiry and hit counts; progressive lockouts (for example 15 minutes, 1 hour, 24 hours, permanent).
* Eight optional public blocklists, each off until you enable it, updated politely and never overriding your allowlist. Each list's licence is shown next to it; some are for non-commercial use only.
* Early firewall: refuses blocked IPs before WordPress loads (auto_prepend_file) or before other plugins (a must-use plugin), from a snapshot kept in a private folder outside the web root.
* The same policy (block rules minus the allowlist) can be written as nginx and Apache deny files and synced to a Cloudflare IP list, so blocked IPs can be stopped before PHP or at the edge.

**Login protection**

* Failed logins are counted per IP and per account. IPs over the limit are locked out; accounts attacked from many IPs accept password logins only from IPs they used before, so attackers cannot lock out the real user. Limits apply to wp-login.php, XML-RPC and REST API application passwords, and are checked before the password is hashed.
* Two-factor authentication: passkeys and security keys (WebAuthn), authenticator apps, email codes and backup codes. Optional, or required for administrators or everyone. Changing a method needs a fresh confirmation with the second factor; wrong confirmations are limited.
* Login location rules: allow or deny logins by country, using Cloudflare's country header, a server variable or the optional free DB-IP database.
* Application password controls, a username enumeration guard, and an option to turn off XML-RPC logins.

**Malware lockdown**

* A read-only scan, twice a day, of the places takeover malware such as "SC" hides: prepend loaders, drop-ins, must-use plugins, hidden plugins and administrators, database triggers, PHP in uploads, encoded payloads, suspicious scheduled tasks and hooks.
* A daily file integrity check of WordPress core and WordPress.org plugins against the checksums WordPress.org publishes.
* Checks for incidents being exploited right now (October 2026: the Rank Math PRO 3.0.123 backdoor, backdoor plugins installed through stolen UpdraftCentral keys, the PHP2Shell flaws in PHP): their files, options, accounts and settings are reported by the scan, their trigger requests and malware servers are refused, and plugin installs are logged with an alert when one looks like a takeover.
* Opt-in measures: an administrator lock (only approved accounts keep admin rights, optionally fixed in wp-config.php), file editor and installs off, PHP blocked in uploads, and alerts on new administrators.

**Monitoring and tools**

* Events log, dashboard, enforcement health card (also `wp sentinel health` for monitoring), and a Scheduled Tasks page that shows every WP-Cron task and lets you pause or run it.
* Alerts by email with a record of whether the mail system accepted each one, an hourly heartbeat for uptime monitors, and an optional remote audit log (signed, hash-chained webhook and syslog) that survives a wiped database.
* Test mode per module, decision and IP simulators, and a full WP-CLI command set (`wp sentinel`).
* Multisite support with network-wide rules.

**Safety**

Your own IP is allowlisted on activation and when you save settings, rules that would block you are refused, WP-CLI and the server's own cron requests are never blocked, and `define( 'SENTINEL_SHIELD_DISABLE', true );` in wp-config.php switches everything off in an emergency. The FAQ lists every way back in.

**Documentation**

Settings → Documentation in the plugin explains every feature and setting with its current value. The same reference is in the source repository: docs/SETTINGS.md (every setting) and docs/ADMINISTRATORS.md (the administrator lock).

== Scope ==

Sentinel Shield blocks by IP address, account and country, hardens logins and detects tampering. It does not include:

* a vulnerability database: it does not warn about known holes in installed plugins and themes, and has no virtual patches for them (except the short list of actively exploited incidents on Settings → Documentation, whose traces it looks for);
* request payload inspection: it does not look for SQL injection, cross-site scripting or similar attacks inside requests, so an exploit sent from an address that is not blocked reaches WordPress;
* DDoS protection: volumetric attacks have to be stopped upstream by your host or a CDN;
* backups or malware removal.

Use it alongside updates, off-site backups and, where you need them, services that provide those.

== External services ==

Nothing below is contacted unless stated as a default or you switch it on.

* **WordPress.org** (on by default, file integrity check): requests the published checksums for your WordPress version and locale (api.wordpress.org) and for each installed plugin and version (downloads.wordpress.org), daily, cached 30 days. Switch off on Settings → Malware Lockdown. Terms: https://wordpress.org/about/privacy/
* **Blocklist providers** (each list off by default): your server downloads each list you enable from its provider (spamhaus.org, iplists.firehol.org, rules.emergingthreats.net, lists.blocklist.de, cinsscore.com, feeds.dshield.org, check.torproject.org) with a generic "SentinelShield" user agent and no site address. The provider sees your server's IP address. Each list's terms are linked on Settings → Blocklists.
* **DB-IP** (off by default): the country database is downloaded from download.db-ip.com, checked weekly. DB-IP sees your server's IP; lookups happen locally. The data is licensed CC BY 4.0: by switching it on you agree that visitors whose login is refused because of a DB-IP lookup see an "IP Geolocation by DB-IP" credit link. Terms: https://db-ip.com/db/lite.php
* **Cloudflare** (only with the Cloudflare preset or sync): Cloudflare's address ranges are fetched weekly from api.cloudflare.com/client/v4/ips. Cloudflare list sync (off by default) sends the addresses and ranges of your block policy to your own Cloudflare account with your API token. Terms: https://www.cloudflare.com/website-terms/ and https://www.cloudflare.com/privacypolicy/
* **Your webhook** (off by default): each event is sent as JSON with the fields id, time, event, module, ip, reason, uri (path and query, with reset keys, nonces, passwords and tokens masked), agent (user agent), user_id, test, context (event details such as the username tried, a country code or a file path), seq, prev and hash, plus the site address.
* **Syslog** (off by default): one line per event with site (host name), id, event, module, ip and reason, written to the server's system log.
* **Your heartbeat URL** (off by default): a plain request every hour, without data.
* **Email**: alerts go to the site admin address, two-factor codes and unlock links to the account's address, through WordPress's mailer.
* **Your own site**: to confirm the private folder cannot be downloaded, the site may request a test file from itself.

== Installation ==

1. In WordPress go to Plugins → Add New → Upload Plugin and choose `sentinel-shield-0.9.0.zip` (or unzip it into `/wp-content/plugins/`).
2. Activate it (on multisite: Network Activate). The plugin starts in **test mode**; nothing is blocked yet and your IP is allowlisted.
3. Go to Sentinel Shield → Settings → IP Detection and confirm "Detected IP" matches your real public IP. If your site is behind Cloudflare or a load balancer, choose the matching preset.
4. Review Sentinel Shield → Events for "would block" entries.
5. Turn off test mode on Settings → General & Test Mode.
6. Set up two-factor authentication for your own account under Users → Two-Factor Authentication, then consider requiring it for administrators on Settings → Login Security.
7. Go to Sentinel Shield → Malware Lockdown, run a scan, check the Administrators list, then switch on the lockdown measures you want on Settings → Malware Lockdown.

The early firewall and the server blocklist files use a private folder, `sentinel-shield-data` next to the WordPress folder. If PHP cannot create it there, or your host serves that folder over the web, set another folder outside the web root with `define( 'SENTINEL_SHIELD_DATA_DIR', '/path/outside/the/web/root' );` in wp-config.php. Settings → Server & CDN shows whether the folder is confirmed private.

Each release zip contains `checksums.sha256` (SHA-256 of every file) and `build.json` (version, git commit and build date). To check an installed copy, run `sha256sum -c checksums.sha256` inside the plugin folder.

== Frequently Asked Questions ==

= I locked myself out. What now? =

Any one of these works:

* Add `define( 'SENTINEL_SHIELD_DISABLE', true );` to wp-config.php, log in, fix the rule, then remove the line.
* Run `wp sentinel unblock <your-ip> --allow-hours=24`.
* Use "Send unlock link" on the block page (403 mode only) with your administrator email address. Unlock emails are limited to one per account every 5 minutes (3 per account and 10 per site per hour), so if nothing arrives, wait or use WP-CLI.

= I am locked out after too many failed logins. What now? =

Wait for the lockout to end (15 minutes the first time by default), or:

* `wp sentinel unblock <your-ip>` lifts the lockout, and `wp sentinel login-attempts --clear --ip=<your-ip>` resets the count.
* If your account is protected after a distributed attack, log in from an IP you used before, or run `wp sentinel login-attempts --clear --account=<your-login>`.
* Add your IP to the allowlist (`wp sentinel allow <your-ip>`): allowlisted IPs are never counted or locked out.

= I lost the phone with my authenticator app. What now? =

Use one of your backup codes, or "Email me a code" if email codes are allowed. Otherwise ask another administrator to tick "Reset two-factor authentication" on your profile, or run `wp sentinel 2fa <your-login> --reset`. As a last resort, the `SENTINEL_SHIELD_DISABLE` constant in wp-config.php turns two-factor off until you remove it. Then set up your app again and create new backup codes.

= Why does XML-RPC or the REST API refuse my password? =

Your account uses two-factor authentication, and those interfaces cannot ask for a code. Create an application password under Users → Profile and use it instead of your normal password. If "Turn off logins over XML-RPC" is on, XML-RPC logins are refused for everyone.

= My administrator rights are suspended. What now? =

The administrator lock is on and your account is not approved. Ask an approved administrator to approve you on Sentinel Shield → Malware Lockdown, or run `wp sentinel approve-admin <your-login>`. If `SENTINEL_SHIELD_ADMINS` is defined in wp-config.php, add your `login#ID` there instead. Without WP-CLI, add the SENTINEL_SHIELD_DISABLE constant, approve yourself on the Malware Lockdown page, then remove the constant.

= My login is refused because of my location. What now? =

The login location restriction does not allow your country, or your country could not be determined and unknown locations are denied. Any one of these works:

* `wp sentinel allow <your-ip>` (allowlisted IPs are never denied by location).
* `wp sentinel settings-set geo.countries "US, CA"` to add your country, or `wp sentinel settings-set geo.mode off`.
* The `SENTINEL_SHIELD_DISABLE` constant in wp-config.php.

`wp sentinel geo <ip>` shows which country an IP is in and why a login would be allowed or denied. Mobile networks and VPNs can appear in another country.

= How accurate is the country lookup? =

Country-level IP databases are about 98-99% accurate. Satellite, mobile and VPN connections are the usual exceptions. Treat the location restriction as one layer of protection alongside strong passwords and two-factor authentication, and use "Applies to: administrator-level accounts only" if customers log in from anywhere.

= What does DB-IP learn about my site? =

Your server downloads the country database from db-ip.com about once a month (with a weekly check whether it changed), so DB-IP sees your server's IP address. Lookups happen on your server; nothing about visitors is sent. The free database is licensed CC BY 4.0, which requires a link back to DB-IP where its results are used. Switching the download on is your consent to that: a visitor whose login is refused because of a DB-IP lookup sees "IP Geolocation by DB-IP" under the message. No credit appears anywhere else on the public site. Use Cloudflare's country header or a server variable instead if you do not want it.

= I cannot install a plugin or theme =

"Block installing and uploading plugins and themes" is on. Untick it on Settings → Malware Lockdown, install, then tick it again, or install with WP-CLI. Updates are never blocked.

= The malware scan found something. Is my site infected? =

Not necessarily: drop-ins, must-use plugins and scheduled tasks are often legitimate. Items marked Critical matched known malware traits and need a close look. If you recognize an item, approve it and you will only be warned again if it changes. If the scan finds SC, follow the cleanup order on the Malware Lockdown page: the order matters, because the copies rebuild each other.

= What does the file integrity check send to WordPress.org? =

Only requests for the published checksums of your WordPress version and locale and of each installed plugin and version, the same information WordPress's own update checks send. Nothing about visitors is sent. Checksums are cached for 30 days. Switch the check off with "Verify core and plugin files against WordPress.org checksums" on the Malware Lockdown tab.

= The file integrity check says files were saved under cut-off names =

WordPress was unpacked by a tool that shortens paths longer than 100 characters (wp core download does this on some systems), so some core files exist only under shortened names and WordPress cannot load them. Reinstall WordPress from Dashboard → Updates → Re-install (or from the official zip from wordpress.org), then delete the shortened copies listed in the finding and run the check again.

= The file integrity check reports a changed plugin file I edited myself =

Approve it on the Malware Lockdown page. You are warned again only if the file changes. Better still, keep custom code in a separate plugin, so updates do not overwrite it.

= The Enforcement health card says "Degraded" or "Problem". What do I do? =

Each row says what is wrong. The most common on new sites: test mode is still on with no end date (turn it off on the General tab once the detected IP is right), or scheduled jobs have not run yet (they need up to a day; if they never run, check WP-Cron on the Scheduled Tasks page). "Concurrency locks: degraded" means your database (often through a proxy such as ProxySQL, or a cluster) gives no named locks; Sentinel Shield uses lock rows instead, which works but is slower.

= Does an automatic allowlist entry exempt my office from login limits? =

No. Entries added automatically when an administrator saves settings only keep that IP from being blocked, so the administrator can always get back in. Everyone else behind the same address still has to stay within the login limits and location rules. Add the address yourself on the IP Rules page if you want to exempt it from those too.

= How do I set up the early firewall? =

On Settings → Server & CDN choose "Before other plugins" (installed automatically as a must-use plugin) or "Before WordPress" and add the auto_prepend_file line shown there to your PHP configuration. The tab and the health card show whether it is running. Its snapshot lives in the private folder (sentinel-shield-data next to the WordPress folder, or SENTINEL_SHIELD_DATA_DIR); the tab shows whether that folder is confirmed private. If the early firewall ever gets in the way, create an empty file named gate.disabled in that folder.

= Do passkeys replace passwords? =

Not yet: a passkey is used as the second step after the password, as the strongest of the two-factor methods. Keep backup codes in case you lose the device; an administrator can reset two-factor for an account.

= What should my webhook receiver do? =

Check the X-Sentinel-Shield-Signature header (HMAC-SHA256 of "<time>.<body>" with the secret shown on the Alerts & Audit Log tab), reject old timestamps, and store the events. To detect tampering, check that seq has no gaps and each event's prev equals the previous event's hash. Answer with any 2xx status; anything else is retried later.

= Why does every visitor have the same IP? =

Your site is behind a proxy and Trusted Proxy is set to None. Pick the matching preset on the IP Detection tab and use the IP resolution simulator on the Tools page to check it.

= What do blocklist providers learn about my site? =

Your server downloads each enabled list directly from its provider (FireHOL Level 1 and IPsum from iplists.firehol.org), so the provider sees your server's IP address and when it checks for updates. Sentinel Shield sends a generic "SentinelShield" user agent without your site address, asks whether the list changed before downloading it again, and sends nothing about your visitors.

= Can I use every list on a commercial site? =

No. As checked in October 2026 (terms can change; each list links to its own on the Blocklists tab):

* Non-commercial only: DShield (CC BY-NC-SA) and FireHOL Level 1, which includes DShield data.
* Free to use: the Spamhaus DROP lists (free of charge under Spamhaus's terms, which forbid using the Spamhaus name in marketing), IPsum (public domain), CINS Army (the provider says "use in any way you see fit") and the Tor exit list (CC0).
* No licence published: Emerging Threats compromised hosts and blocklist.de are offered as free downloads ("as is, at your own risk") without stated terms; decide yourself whether that is enough for your site.

= Does test mode protect anything? =

No. Test mode only records what would have been blocked. Use it to validate settings, then turn it off. Malware Lockdown measures are the exception: they are always enforced once switched on.

== Changelog ==

= 0.9.0 =
Detection and prevention for the incidents exploited against WordPress sites in the week of 16 to 23 October 2026. The malware scan has a new check, "Recent incidents", and the Malware Lockdown tab four new settings (three on by default; they only refuse traffic no legitimate site sends).
* Rank Math PRO 3.0.123 supply-chain backdoor (CVE-2026-111862): the scan reports Rank Math PRO 3.0.123 (critical when its files were written after the bad build appeared at 20:02 UTC on 15 October), the backdoor's three options, the fake core file wp-includes/class-wp-cache-util.php, .htaccess rules that run .cache files as PHP, .cache files containing PHP, administrators named wpsupport_… or with @wp-mail.net addresses, and SSH keys of the account PHP runs as. When any of these is found, plugins, must-use plugins and themes are searched for the backdoor's code. New code signatures: its XOR key, its server, its crontab tag, base64 payloads decoded with XOR, and proc_open.
* "Block known malware servers" (on): requests from the site to rank1cdn.com, the backdoor's server, are refused and logged with the file that made them. Separate from the blockchain gateway setting.
* UpdraftCentral key theft (18 and 19 October): the scan reports plugins carrying the backdoors' marker text or trigger parameter (critical) or one of their names (warning, can be approved), the accounts they create, administrators with @example.com addresses, UpdraftPlus versions that accept forged commands (before 1.26.5 / 2.26.5) or still accept the stolen keys (before 1.26.13 / 2.26.13, with keys stored), and keys created before the theft.
* "Refuse requests carrying attack markers" (on): the backdoors' trigger parameter and the campaign's two addresses (unless allowlisted) get a 403 and an event. "Refuse UpdraftCentral remote commands" (off): for sites not managed from UpdraftCentral.
* "Log plugin installs and alert on suspicious ones" (on): every plugin install and activation is logged with the account and channel (dashboard, WP-CLI, REST API, XML-RPC, scheduled task, UpdraftCentral command). The site admin is emailed when the plugin carries a backdoor marker, arrived through an UpdraftCentral command, or was installed with no logged-in user.
* PHP2Shell (CVE-2026-109618, CVE-2026-109619): the scan and the health card report a PHP build older than 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (critical) or a distribution build whose fix cannot be told from its version (warning; approve it once the changelog confirms the backport), with the stopgap settings still missing (session.upload_progress.enabled, fatal_error_backtraces). Malformed PHPSESSID cookies, which the probes send, are refused and logged. The attack runs before any plugin loads: only updating PHP prevents it.
* Settings → Documentation lists the incidents with their sources.
The new measures work while the Malware Lockdown module is on, like the other lockdown measures.

= 0.8.6 =
Stabilization from a sixth review: deadlines, lost locks and Cloudflare concurrency. No new features.
* Hourly housekeeping keeps to its time budget as a deadline: no step or database batch starts after it, a policy build starts only if the last one would fit (otherwise its own background job builds now), and whatever is left continues five minutes later. The report lists the steps that waited.
* The monitoring heartbeat and audit-log delivery have their own background jobs instead of running inside housekeeping; delivery requests never wait past the time left, and a delivery cut short continues a minute later.
* Lost locks stop the work they protected: a database reconnect (which releases MySQL named locks) or a lock row taken over after its lease is noticed, and the early firewall build, the audit export and the file integrity scan stop before their next change. A build that lost its lock publishes nothing; an audit batch is sent again by the next run with the same sequence numbers, so the hash chain never forks.
* Cloudflare: scheduled syncs, confirmation checks, Sync now, WP-CLI, settings changes, token removal and deactivation update the list one at a time. Scheduled work waits its turn; Sync now and WP-CLI wait up to 20 seconds and say so if another update is still running. Answers from Cloudflare apply only to the operation they are about, so a late answer never overwrites a newer upload.
* Uninstall also clears the audit delivery, heartbeat and Cloudflare jobs.
* Upgrades from 0.8.0: a request still running the old code during the update (a background cron run, say) could write the old snapshot, with its allowlist, back into the public uploads folder after the one-time cleanup, where it stayed. Hourly housekeeping now removes any such file.
Testing (not shipped; see docs/TESTING.md): tests for each deadline and lost-lock path, a race of simultaneous WP-CLI syncs against a stand-in Cloudflare API on nginx and Apache with PHP-FPM (the previous code overlapped 15 uploads in it, this one none), 11 more mutants (64, all caught), and coverage jobs that fail when a required report or any source file in a measured area is missing. That check found two files no test loaded (the block page's unlock-form token and the multisite per-site settings page); both have tests now.

= 0.8.5 =
Release tooling only; the plugin code is the same as 0.8.4.
* CI: composer audit is retried when packagist cannot be reached (findings still fail at once); the browser passkey test waits longer for Chrome and reports why it did not start.
* Builds: test builds of commits after a release are allowed with bin/build.sh --dev and marked "development": true in build.json; release builds from tags stay strict.
* Upgrade tests now also start from 0.8.4.

= 0.8.4 =
0.8.3 was tagged but not released (its CI run found the two server-file and cache issues below); 0.8.4 contains all of it.
Evidence before features: a fifth review asked for measurable testing under failure and load. Changes users notice:
* Passkeys: a new setting, Passkey user verification. By default a security key that only checks a touch is accepted after the password; "Always require" asks for fingerprint, face or PIN at login and when adding a key, and refuses responses without it. Confirming identity with a passkey alone (no password) now always requires that check. Without PHP's OpenSSL extension only Ed25519 passkeys are offered and the health screen says so, instead of a fatal error at login.
* Policy publication is durable and off visitors' requests: a change made by a visitor's request (a lockout at the login form) is published by a background job; the marker survives a build that dies half-way, a change that arrives during a build is not lost, and the health screen warns when publication is overdue (WP-Cron not running).
* Writes that a full disk cuts short are detected (snapshot files, gate.json, server files); nothing partial is published and the previous policy stays in use. Stray temporary files from killed builds are removed. A private folder later replaced by a symlink is checked again, and missing or damaged range files show on the health screen.
* Cloudflare: Retry-After on rate limiting is respected, and every list update is recorded before it is sent, so a worker killed after the upload leaves an "unknown" state that is retried and emptied when sync is switched off, never a list that is forgotten.
* Storage budgets: caps for the event log, the waiting audit backlog (days and rows, with the gap counted) and the login history (never inside the counting window; the limits use separate counters), and a time budget per housekeeping run that continues five minutes later if work is left.
* Uninstall with "delete data" now also removes the login counter table and per-site transients. WP-CLI settings-get reports unknown keys. Rebuild now (and wp sentinel early-gate rebuild) waits for a build already running instead of silently doing nothing.
* One query instead of six on every page for the plugin's own options.
* Server files are never deleted while nginx or Apache may include them: switching every layer off, or a data folder that cannot be confirmed private, now leaves them emptied (a missing include stops the web server from reloading).
* With a persistent object cache, a cached block match is checked against its rule's expiry on every read.
Testing (not shipped; see docs/TESTING.md): line coverage 82% (from 61%), with floors per security area that a change may not lower, and branch coverage nightly; 53 deliberate defects that the tests must catch (mutation testing); an authorization matrix of every admin action by every kind of account and nonce; simultaneous HTTP requests racing for one backup code, authenticator code, passkey response or confirmation (exactly one wins); workers killed with SIGKILL during publication, Cloudflare sync and while holding locks; live nginx and Apache configuration tests; nginx and Apache with PHP-FPM; a Cloudflare API fake with timeouts, 429s, malformed answers and slow or failed operations; install, upgrade (0.8.0 to 0.8.2), deactivation and uninstall matrix; WordPress in a subdirectory, a moved content folder and a domain-mapped multisite; HTTPS behind a proxy and passkeys synchronized between two browsers; fuzzing of every parser; clock, filesystem, cache and privacy tests; PHPStan level 6, dependency audit and secret scanning; full-stack performance budgets. Release zips are built and attested in CI.

= 0.8.2 =
Fixes from a fourth code review of the new enforcement layers:
* Private folder: a folder counts as private only on positive evidence. Outside the document root (now remembered from web requests, so WP-CLI and cron use it too), or inside it with a test file refused while a control file in uploads is served, over a verified TLS connection; that HTTP evidence is re-checked daily. A folder whose URL could not be worked out was wrongly approved before; it is now "not confirmed", and so is a challenge page that refuses everything.
* Upgrading removes what 0.8.0 left in the public uploads folder: the snapshot, range files and block log are deleted, and the old server files are replaced with stubs that block nothing, so existing include lines keep working until you change them. Files that cannot be removed are reported on the Server & CDN tab and the health card, and removal is retried hourly.
* Cloudflare: uploading and emptying share one state (applying, then confirmed active or empty, or failed or unknown and retried). A list counts as emptied only once Cloudflare confirms it. Removing the API token empties its list first (the token is kept if that cannot be confirmed), a list the settings no longer point at is emptied and tracked until confirmed, and deactivation waits a few seconds for Cloudflare and emails the site admin how to finish by hand if it does not confirm. Cloudflare mirrors the published policy generation.
* Identity confirmation on the two-factor page runs under the account's two-factor lock and re-reads stored values after taking it, so parallel requests cannot share the failure budget or reuse a code, backup code or passkey challenge.
* Each early firewall generation is published as a whole: range files with names unique to the build, every write checked, then one atomic switch of gate.json. A failed build keeps the previous generation and is retried after five minutes. Server file writes are checked too.
* Expiry is described as it is: WordPress applies it immediately, other layers eventually (WP-Cron can run late, Cloudflare confirms asynchronously, web servers need a reload). The snapshot no longer lives at least a minute longer than the rule that expires first. The Server & CDN tab shows per layer which policy generation is wanted, published and confirmed.
* Performance: range subtraction is a single sweep (20,000 blocked ranges minus 10,000 allowed addresses: 0.03 s instead of 22 s); rebuilds during a burst of lockouts are published at most every 10 seconds; undelivered audit events are kept through retention pruning (up to 90 days, with gaps counted) and the age of the oldest waiting event is shown. bin/bench-early-gate.php measures the early firewall: with 50,000 or 500,000 blocked ranges its throughput stayed within measurement noise of a one-line PHP page, both when letting requests through and when refusing a flood.

= 0.8.1 =
Stabilization release from a third code review:
* One policy everywhere: the early firewall, the nginx and Apache files and the Cloudflare list now block exactly what WordPress blocks, the enforced block rules minus the allowlist and this server's addresses (ranges are split around allowed addresses). Before, an allowlisted IP inside a blocked range was refused by the server files and Cloudflare. Each change gets a generation number shown on the Server & CDN tab.
* Switching off works on every layer: with protection or the IP gate off, every layer gets an empty policy; turning Cloudflare sync off or deactivating the plugin empties the Cloudflare list (with a warning if that fails); deactivation removes the must-use loader and the snapshot and empties the server files.
* Private folder: the snapshot (which contains allowlisted addresses), the block log and the server files moved out of uploads to a folder outside the web root (sentinel-shield-data, or SENTINEL_SHIELD_DATA_DIR). Nothing is written until the folder is confirmed private; .htaccess rules are not relied on, so nginx sites are covered.
* Short lockouts reach the other layers sooner: the policy is rebuilt when the next temporary rule expires, not only hourly.
* Cloudflare: the list is shown as active only after Cloudflare confirms its bulk operation; uploads happen at most every five minutes and only when the list changed; single IPv6 addresses are left out by default (new IPv6 setting) and never widened over an allowlisted address. Cloudflare's own address ranges now come from its API.
* Identity confirmation for two-factor changes needs the second factor (passkey, or password plus an app or backup code) and is limited to five tries in 15 minutes; failures count toward the login limits.
* Fallback lock rows record their owner, so a slow process can no longer release a lock another process took over; long jobs renew their lock.
* Remote audit log delivery moved from the end of visitors' requests to a background job; the early firewall samples its block log during floods and logs paths without query strings; event URIs mask reset keys, nonces, passwords and tokens.
* Plugin Check clean; FireHOL and IPsum lists download from iplists.firehol.org; alert status says "accepted by the mail system"; blocklist terms re-checked and labelled; the DB-IP credit link is described as part of switching DB-IP on; a scope statement and an external services section in this readme. The settings reference moved to docs/SETTINGS.md and the Documentation tab.
* CI: WP-CLI for the smoke test is installed from a pinned, checksum-verified release (a failed tool download had stopped one run before the plugin was tested), and Plugin Check runs against the release zip.

= 0.8.0 =
* Passkeys and security keys (WebAuthn) as a two-factor method: added on the Two-Factor Authentication page, used with one tap on the login code screen; ES256, EdDSA and RS256 keys, signature counters checked, challenges single-use. Tested end to end in Chrome with a virtual authenticator.
* Fresh confirmation: adding or removing a two-factor method or creating backup codes needs the password or a passkey within the last 10 minutes of the same login session; administrators confirm their own password to reset another user's two-factor.
* Early firewall (early-gate.php): blocks listed IPs before WordPress loads (auto_prepend_file) or before other plugins (must-use plugin), from a snapshot WordPress keeps current; steps aside whenever anything is unclear. Emergency switch: a gate.disabled file.
* Server and edge blocking: nginx and Apache blocklist files kept up to date, Cloudflare IP list sync, and wp sentinel server-export.
* Remote audit log: security events sent to a webhook as they happen (HMAC-signed, hash-chained, retried with backoff), optional syslog, wp sentinel audit-export.
* Alert monitoring: whether the mail system accepted each email is recorded and refusals shown on the health card, a test for every channel, and an hourly heartbeat for monitoring services.
* Health card: early firewall, Cloudflare sync, alert emails, audit delivery and heartbeat rows.

= 0.7.0 =
Security and performance work from a second code review:
* REST API application passwords: wrong ones are now counted toward the login limits (they were not), and a limited IP or account is refused before the password is checked (HTTP 429). XML-RPC logins are not counted twice.
* A lockout no longer erases the locked-out IP's failures from the accounts it tried: enforcement uses new atomic per-minute counters, and only the IP's own count restarts. Before, rotating IPs could keep an account under its distributed-attack limit.
* Login limits are checked before WordPress checks the password, so refused logins cost no password hashing, and the per-IP lock now covers the password check. A login from an IP that a parallel request has just locked out is refused too.
* Trusted browsers: each one is listed (browser, IP, added, last used) and can be revoked on its own; a password change or reset, or adding, replacing or removing an authenticator app or email codes, revokes them all along with any open code screens.
* Two-factor limits are per account: at most 10 code screens, 6 emailed codes and 15 wrong codes an hour, and up to three code screens can be open at once, so restarting the login resets nothing and cannot cancel someone else's. Codes are emailed after the account lock is released.
* Concurrency locks: when the database gives no named lock, a lock row is used instead; when no lock can be taken at all, the operation is refused rather than run unprotected. Lock waits are shorter (1 second for logins, 2 for code checks).
* Automatic administrator allowlist entries keep an IP from being blocked but no longer exempt it from login limits or location rules.
* Enforcement health card on the dashboard and `wp sentinel health`.
* Application password controls: block them for administrator-level accounts or everyone, expire them after N days, retire unused ones; administrators' application passwords are listed on the Login Security tab.
* Performance: blocklists are compiled into a compact file and looked up with a few small reads (one worker compiles, others query the database meanwhile); with a persistent object cache, rule matches are cached and hit counts written at most once a minute; the rule lists are rebuilt by one worker at a time; old rows are deleted in small batches; large files are fingerprinted without reading them whole; admin report figures are cached for a minute.
* CI: the smoke test now checks REST application passwords over HTTP and 20 simultaneous logins against a multi-worker server, and the integration tests also run with a Redis persistent object cache.

= 0.6.1 =
* File integrity check: files that are intact copies of official files saved under shortened names (paths over 100 characters cut off when the package was unpacked, as wp core download does on some systems) are now reported as one "damaged installation" finding with the fix, instead of one possible-backdoor warning per file. A shortened name with any other content is still reported as an added file.
* File integrity check: every reported file is now checked for malware code whatever its name, so code hidden in a file without a .php extension in a core folder is critical.
* CI fixes found by the first GitHub run: a PHP 8.1 incompatibility in a test helper, a flaky encryption test, and the smoke test now builds its site from the official WordPress tarball and shows the output of a failing scan.

= 0.6.0 =
* File integrity check: WordPress core and plugins from WordPress.org are compared daily with the file hashes WordPress.org publishes for the installed versions. Changed core files and files no release contains in wp-admin or wp-includes are critical; changed or added PHP files in plugins are warnings. Runs in slices that keep their place, so large sites are checked completely; every pass reports what was verified and what could not be (themes, premium and single-file plugins) and why. Shown on the Malware Lockdown page, emailed like scan findings, approvable, and available as `wp sentinel verify`.
* Malware scan coverage: every scan reports how many files it read, which large files it could only read partly, and which files or folders it could not read. The uploads folder is no longer cut off at 20,000 files: the walk keeps its place and continues in the next runs until every file is checked, carrying earlier findings along. `wp sentinel scan` checks everything in one go.
* Automatic administrator allowlist entries (added on activation and when settings are saved) now last 30 days and renew while an administrator uses the dashboard from that IP, so addresses nobody uses any more stop being trusted. Configurable on the Lockouts & Unlock tab (0 keeps them forever). Existing automatic entries get the same 30 days on upgrade; entries you added yourself are not changed.
* Security regression CI: coding standards, unit tests on PHP 8.1 to 8.4, the integration tests on WordPress 6.4 and the latest version as single site and multisite, and an end-to-end smoke test of a real site over HTTP. New scripts: `bin/install-wp-tests.sh` and `bin/smoke-test.sh`.
* Tests now run on multisite too; test helpers create network administrators where administrator-level accounts are meant.

= 0.5.1 =
Security fixes from a code review:
* Trusted proxies: a request from a trusted proxy that does not name the visitor (forwarding header missing, empty, malformed or listing only trusted proxies) is now always treated as anonymous, with none of the proxy's allowlist or server exemptions. Before, a missing or empty header or a proxy-only chain kept them. The IP Detection tab warns when this happens.
* Login location: a country server variable that is really a request header (a name starting with HTTP_) is only used on requests that came through a trusted proxy that named the visitor. Before, any visitor could send it.
* Unlock links: a link only works while its account still exists and may manage the site, and unused links are invalidated when the account is deleted or demoted. Unlock emails are now also limited per account (one every 5 minutes, 3 an hour, at most 2 unused links) and per site (10 an hour), and all the limits are checked under a database lock, so parallel requests cannot get past them.
* Two-factor authentication: an account that is required to use it but has no usable method (email codes switched off and no app, or an unreadable app secret with no backup codes) is now refused instead of being let in with its password. The Login Security tab lists such accounts, and you cannot switch email codes off while your own login needs them. Code checks and code emails now run one at a time per account, so parallel requests cannot share the five tries or use a one-time code twice.
* Brute-force protection: logins from one IP now run one at a time from the limit check until the failure is counted, so parallel requests cannot all pass the check before any failure is recorded. A login that would have to wait more than 3 seconds is refused and not counted.

= 0.5.0 =
* Login brute-force protection: failed logins (including unknown usernames and wrong two-factor codes) are counted per IP and per account. IPs over the limit are locked out with the progressive lockouts and the login in progress is refused, so XML-RPC multicall cannot get around the limit. Accounts attacked from many IPs accept password logins only from IPs they used before. Refusals do not depend on the password. Also: one message for wrong usernames and passwords, an instant lockout username list, an option to turn off XML-RPC logins, failed-login overview on the new Login Security tab, and WP-CLI `login-attempts`.
* Two-factor authentication: authenticator apps (QR code drawn on your server), email codes and backup codes, set up by each user under Users → Two-Factor Authentication. Can be required for administrators or everyone; required accounts without an app get email codes and a reminder. Encrypted secrets, single-use codes, five tries per login, optional "Trust this browser", administrator reset from the profile, and WP-CLI `2fa`.

= 0.4.0 =
* Login location (GeoIP) restriction: allow logins only from listed countries or block listed countries, for all accounts or administrators only, on wp-login.php, XML-RPC and application passwords. Country from Cloudflare (verified), a server variable, or the free DB-IP country database (downloaded and updated automatically; a compact local file, about 10 µs per lookup). Unknown-country policy, allowlist bypass, test mode, self-lockout protection, a status panel with IP lookup on Settings → Login Location, and WP-CLI `geo` and `geo-update`.

= 0.3.0 =
* `SENTINEL_SHIELD_ADMINS` in wp-config.php: fixes the approved administrator list in a file (logins, optionally pinned to user IDs) so database writes cannot change it, and always enforces the administrator lock. Unmatched or re-registered entries are flagged on the Administrators list, in an admin notice and by the malware scan.
* Fixed: an account locked by the administrator lock could not open its own profile page (where the lock is explained); it now can, and still cannot edit anyone else.

= 0.2.0 =
* Documentation tab (Settings → Documentation): administrator approvals explained in detail with the current approved list, every setting with its key, default and recommended value, wp-config.php constants, recovery steps and WP-CLI commands. The readme's settings reference is generated from the same source.
* Release builds: `bin/build.sh` checks version numbers, coding standards and tests, and produces an install zip with `checksums.sha256` and `build.json`. The source is now under git, with each release tagged.
* Malware Lockdown against the "SC" WordPress malware (Sucuri, September 2026): a read-only scan of every SC persistence point twice a day with email alerts and per-item approval; opt-in measures: administrator lock, file editor off, plugin/theme installs off, PHP blocked in uploads, blockchain RPC traffic blocked, protection against deactivation by code, and alerts on new administrators. WP-CLI: scan, admins, approve-admin, revoke-admin.
* Fixed the "translation loading triggered too early" notice on the block page (WordPress 6.7+).
* Scheduled Tasks page: WP-Cron monitor with last-run status, failures, callback origins and WP-CLI commands, plus run now, pause/resume (paused tasks cannot be re-added by their plugin), change schedule and delete. Deactivation resumes paused tasks.
* Blocklist feeds: eight opt-in public lists with scheduled, additive updates; plain-text list upload on the IP Rules page.
* Security hardening from a penetration test: unlock links need an explicit confirmation (email scanners cannot use them, and the requesting IP is only unblocked when the admin ticks it), blocked-request logging is throttled per IP and capped site-wide without an object cache, loopback and proxy addresses are never auto-allowlisted and requests that fall back to a proxy's IP get no allowlist privileges, and over-broad trusted proxy ranges (such as 0.0.0.0/0) are refused.

= 0.1.0 =
* Phase 1: core framework, client IP detection, IP rules, lockout engine, lockout safety, test mode tooling, events, WP-CLI.

== Upgrade Notice ==

= 0.9.0 =
Detects and blocks the Rank Math PRO backdoor, the UpdraftCentral backdoor plugins and PHP2Shell probes (October 2026), and alerts on suspicious plugin installs. Turn on the Malware Lockdown module if it is off, then run the scan.

= 0.8.6 =
Housekeeping keeps to its time budget, work that lost its lock stops safely, and Cloudflare list updates run one at a time. No settings change.

= 0.8.5 =
No plugin changes since 0.8.4; release tooling and CI only.

= 0.8.4 =
New passkey verification setting, durable background policy publication, storage limits, full-disk and crash safety, and a much larger test suite. Uninstall now removes all data it should. No action needed.

= 0.8.2 =
Deletes 0.8.0 runtime files left in public uploads, confirms Cloudflare cleanup before reporting it, and approves a private folder only on positive evidence. If you included the old uploads server files in nginx or Apache, switch to the new path shown on Server & CDN.

= 0.8.1 =
Fixes allowlist precedence at the web server and Cloudflare, empties external blocklists when protection is off, and moves runtime files to a private folder outside the web root. If the Server & CDN tab reports a folder problem, set SENTINEL_SHIELD_DATA_DIR.

= 0.8.0 =
Adds passkeys, a fresh password confirmation before changing two-factor methods, an early firewall that runs before WordPress, nginx/Apache/Cloudflare blocking, a signed and hash-chained remote audit log, and alert email status. New features are off until you switch them on.

= 0.7.0 =
Login limits for REST application passwords and before password hashing, revoked trusted browsers on password changes, and a health card. Automatic admin allowlist entries no longer exempt an IP from login limits. Trusted browsers must be trusted again once.

= 0.6.1 =
Clearer file integrity results for WordPress installs damaged by unpacking tools that shorten long file names.

= 0.6.0 =
Adds a daily check of core and plugin files against WordPress.org checksums, scan coverage reporting with a resumable uploads walk, and expiring automatic administrator allowlist entries (30 days, renewed while used; existing automatic entries get 30 days).

= 0.5.1 =
Security fixes: trusted proxy fallback, header country variables, unlock link limits, required two-factor without a method, concurrent logins. If you require two-factor with email codes off, check the Login Security tab for accounts that can no longer log in.

= 0.5.0 =
Adds login brute-force protection (on by default: 5 failed logins in 15 minutes lock an IP out, allowlisted IPs excepted) and two-factor authentication (optional until you require it on Settings → Login Security).

= 0.4.0 =
Adds the login location (GeoIP) restriction. It is off until you choose a mode and countries on Settings → Login Location.

= 0.3.0 =
Adds the optional SENTINEL_SHIELD_ADMINS wp-config.php constant for a file-based administrator list. Nothing changes unless you define it.

= 0.2.0 =
Adds Malware Lockdown (SC malware scan and opt-in hardening), blocklist feeds, the Scheduled Tasks page and a Documentation tab. All new protections are off until you switch them on.
