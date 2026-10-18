=== Sentinel Shield ===
Contributors: sentinelshield
Tags: security, firewall, two-factor, brute force, login
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.5.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-hosted firewall, brute-force protection, two-factor authentication, IP blocklists, login location restriction and malware lockdown. No paid cloud service required.

== Description ==

Sentinel Shield is a self-hosted security plugin. Everything runs on your server; optional external integrations are off by default.

**Firewall and IP rules**

* Spoof-resistant client IP detection. Uses REMOTE_ADDR by default and reads forwarding headers only from trusted proxies. Presets: None, Cloudflare (ranges auto-updated weekly), load balancer with custom header, custom CIDR list. The settings page shows the detected IP and raw headers.
* IP allowlist and blocklist for single IPs, CIDR ranges and IPv6, with reason, source, created/expiry time and hit counts. CSV and plain-text import, CSV export.
* Public blocklist feeds (all opt-in, one checkbox each): Spamhaus DROP, FireHOL Level 1, Emerging Threats compromised hosts, blocklist.de, CINS Army, IPsum, DShield top 20 and Tor exit nodes. Lists combine additively, update on a polite schedule (twice daily to weekly, never more often than the provider allows, conditional requests, random jitter, backoff on errors), never include private/reserved ranges, and never override your allowlist.
* Progressive lockout engine (for example 15 min → 1 h → 24 h → permanent).

**Login brute-force protection**

* Failed logins (wrong passwords, unknown usernames, wrong two-factor codes) are counted per IP and per account over a sliding window. An IP over the limit (5 failures in 15 minutes by default) is locked out with the progressive lockouts (15 min → 1 h → 24 h → permanent), and the login in progress is refused, so XML-RPC multicall cannot try hundreds of passwords in one request.
* Distributed attacks: an account with too many failures from many IPs (20 by default) accepts password logins only from IPs it logged in from before (and allowlisted IPs) until the failures age out. No IP gets locked out for this, so attackers cannot use it to lock out the real user.
* Refusals do not depend on the password. Optional: one message for wrong usernames and wrong passwords (on by default), instant lockout for usernames like "admin" that nobody uses, and XML-RPC logins turned off.
* The Login Security tab lists the IPs and accounts with the most failed logins; test mode logs "would deny login" and "would lock out".

**Two-factor authentication**

* Authenticator apps (TOTP, with a QR code drawn on your own server), codes by email, and one-time backup codes. Each user sets it up under Users → Two-Factor Authentication.
* Optional for everyone, or required for administrator-level accounts or every account. Required accounts without an app get a code by email until they set one up, plus a dashboard reminder.
* Works with wp-login.php, the session-expired login popup and other login forms that use WordPress's login (such as WooCommerce). Password logins over XML-RPC and the REST API are refused for two-factor accounts; application passwords keep working.
* Authenticator secrets are encrypted with keys from wp-config.php; backup and email codes are stored only as keyed hashes. Codes cannot be reused, five wrong codes cancel the login, and each wrong code counts toward the brute-force limits. Optional "Trust this browser" for a set number of days.
* Administrators can reset a user who lost their phone from the user's profile or with `wp sentinel 2fa <user> --reset`.

**Login location (GeoIP) restriction**

* Allow logins only from the countries you list, or block logins from listed countries, for every account or administrator-level accounts only. Covers wp-login.php, XML-RPC and application passwords (REST API).
* The answer does not depend on the password, so a visitor from a denied country cannot use the login form to test passwords.
* Country sources: Cloudflare's CF-IPCountry header (only when requests really come through Cloudflare), a country variable set by your server (mod_geoip, MaxMind module) and the free DB-IP country database, downloaded and kept current automatically (no account or key needed).
* Allowlisted IPs and this server are never denied; you choose what happens when the country is unknown. Saving settings that would deny your own next login switches the feature to test mode instead of locking you out. Test mode logs "would deny login" without denying.

**Malware Lockdown**

Protection against the "SC" WordPress malware (described by Sucuri in September 2026) and similar takeovers, which keep copies of themselves in many places and rebuild each other.

* A read-only malware scan, twice a day and on demand, of every place SC hides: auto_prepend_file loaders in .user.ini / php.ini / .htaccess, the db.php and advanced-cache.php drop-ins, must-use plugins and duplicate plugins, plugins hidden from the Plugins screen, administrators hidden from the Users screen, database triggers, injected theme code, hidden PHP files and ZIP bundles, PHP in uploads, encoded payloads and sc_ options in the database, random scheduled tasks, login-capturing and hiding hooks, shared memory and blockchain traffic. New findings are logged and emailed; known-good items can be approved and are reported again if they change.
* Opt-in measures: administrator lock (only approved administrators keep admin rights), file editor off, plugin/theme installs off, PHP blocked in uploads, blockchain RPC command channels blocked, protection against being switched off by code, and alerts on new administrators.
* Malware Lockdown page with the scan, the administrator list (approve and withdraw), "Log out everyone", server configuration checks and the safe cleanup order.

**Monitoring and tools**

* Scheduled Tasks page (WP-Cron monitor): every task with its schedule, next and last run, failures and the PHP error that stopped it, the code it calls and where that code lives. Run now, pause/resume, change schedule and delete. Highlights overdue tasks, tasks with no code and tasks whose code lives in uploads or eval()'d code.
* Security events log, dashboard and admin bar counter.
* Test mode everywhere: global log-only mode with optional auto-expiry, per-module overrides, a decision simulator, an IP resolution simulator, a lockout tester, a block page preview and a test unlock email.
* Documentation tab (Settings → Documentation) with this whole reference, generated from the plugin's own settings, plus the current administrator approvals.
* Multisite: network-wide rules and settings; per-site overrides for the block page.
* WP-CLI: `wp sentinel status|check|resolve-ip|block|allow|unblock|remove|list|lockout|test-mode|settings-get|settings-set|settings-keys|settings-export|settings-import|cloudflare-update|cron|feeds|feeds-update|login-attempts|2fa|geo|geo-update|scan|admins|approve-admin|revoke-admin|flush-cache|prune|unlock-link|events`.

**Lockout safety**

The admin's IP is auto-allowlisted on activation from wp-admin and on every settings save, a warning appears if your own IP matches a block rule, rules that would block your own IP are refused, and wp-cron.php from the server plus all WP-CLI requests are never blocked. See "I locked myself out" below for the ways back in.

**Roadmap:** 404 flood blocking, WAF (auto_prepend_file), file integrity against wordpress.org checksums, audit log and the full dashboard.

== Installation ==

1. In WordPress go to Plugins → Add New → Upload Plugin and choose `sentinel-shield-0.5.1.zip` (or unzip it into `/wp-content/plugins/`).
2. Activate it (on multisite: Network Activate). The plugin starts in **test mode**; nothing is blocked yet and your IP is allowlisted.
3. Go to Sentinel Shield → Settings → IP Detection and confirm "Detected IP" matches your real public IP. If your site is behind Cloudflare or a load balancer, choose the matching preset.
4. Review Sentinel Shield → Events for "would block" entries.
5. Turn off test mode on Settings → General & Test Mode.
6. Set up two-factor authentication for your own account under Users → Two-Factor Authentication, then consider requiring it for administrators on Settings → Login Security.
7. Go to Sentinel Shield → Malware Lockdown, run a scan, check the Administrators list, then switch on the lockdown measures you want on Settings → Malware Lockdown.

Each release zip contains `checksums.sha256` (SHA-256 of every file) and `build.json` (version, git commit and build date). To check an installed copy, run `sha256sum -c checksums.sha256` inside the plugin folder.

Developers: run `composer install` for the test and coding-standards tools, and `bin/build.sh` to build a release zip. The plugin has no runtime Composer dependencies.

== Administrator approvals ==

With the **Administrator lock** on (Settings → Malware Lockdown), only accounts on an approved list keep administrator rights. Any other account with administrator powers is treated as having no capabilities, however it got them. This stops backdoor administrators such as the one SC writes straight into the database and hides from the Users screen.

= Where it is configured =

* Sentinel Shield → Malware Lockdown → Administrators: lists every administrator account read directly from the database, including hidden ones, with Approve and Withdraw approval buttons.
* WP-CLI: `wp sentinel admins`, `wp sentinel approve-admin <user>`, `wp sentinel revoke-admin <user>` (user ID, login or email).
* Settings → Documentation shows the current approved list with who approved each account and when.
* Or fix the list in wp-config.php with `SENTINEL_SHIELD_ADMINS` (below), which replaces the database list entirely.

The list is stored in its own option (`sentinel_shield_admin_approvals`, network-wide on multisite). It is not a settings field, is not included in settings export/import and cannot be changed with `settings-set`, so importing settings never approves accounts. Approving or withdrawing needs full administrator rights (manage_options; manage_network_options on multisite); a locked account cannot approve itself.

= Fixing the list in wp-config.php =

A list in the database could be changed by malware that writes to the database. To fix the list in a file instead, add this to wp-config.php above "That's all, stop editing!":

`define( 'SENTINEL_SHIELD_ADMINS', 'admin#1, jane#7' );`

* Entries are logins separated by commas (an array also works), matched without regard to case.
* `#ID` pins an entry to one account: `jane#7` approves login jane only while it belongs to user ID 7. Always pin: without it, if the jane account is deleted, anyone who registers a new account called jane becomes an approved administrator. The Administrators list shows the ID to use.
* While the constant is defined the lock is always enforced, regardless of the "Administrator lock" checkbox, the Malware lockdown module and "Enable protection" (all stored in the database). Only `SENTINEL_SHIELD_DISABLE` switches it off.
* The database list is ignored but kept; remove the constant to return to it. The Approve/Withdraw buttons and `approve-admin` / `revoke-admin` are disabled.
* The list is applied exactly as written: if no entry matches an administrator (a typo, or an empty value), every administrator is locked until wp-config.php is fixed. Check the Administrators list right after saving the file.
* Entries matching no account, or whose login now belongs to another user ID, are shown on the Administrators list, reported by the malware scan and announced in an admin notice.
* Adding an administrator: create or promote the account, then add its `login#ID`. Removing one: delete its entry (and ideally its administrator role).
* Limit: the list is only enforced while Sentinel Shield runs. Malware writing to the database directly could still remove Sentinel Shield from the active plugins (you would see it deactivated), and malware that can edit files can edit wp-config.php.

= Which accounts count as administrators =

* Single site: the Administrator role, or any account given one of these capabilities directly whatever its role: manage_options, activate_plugins, install_plugins, edit_plugins, edit_files, update_core. Such accounts are flagged "Admin powers without admin role".
* Multisite: super administrators. Ordinary site administrators are not affected.
* Accounts are found with a direct database query and compared with what the Users screen shows; accounts missing from the Users screen are flagged "Hidden from Users screen".

= How it behaves =

* **Turning it on:** if no one is approved yet, every administrator the Users screen shows is approved automatically, plus you. Hidden accounts are never approved automatically. Check the list for accounts you do not recognize first.
* **Empty list:** while no account is approved the lock does nothing, so switching it on (or withdrawing every approval) can never lock out every administrator.
* **New administrators:** have no rights until approved. Approved administrators see a "waiting for approval" notice, and the site admin email gets a "New administrator account" message saying who made the change and from which IP (if "Alert on new administrator accounts" is on).
* **Locked accounts:** can log in and see their profile, but every admin screen and capability is refused, including through the REST API, AJAX and XML-RPC. They see a notice explaining how to get approved. Each locked account is logged once an hour as "Unapproved administrator denied".
* **Withdrawing:** you cannot withdraw your own approval from the admin. Approvals are bound to user ID and login, so an account whose login is changed must be approved again. Removing someone's administrator role does not remove their approval; withdraw it when someone leaves.
* Approvals and withdrawals are written to the Events log.
* **Limit:** without `SENTINEL_SHIELD_ADMINS` the list lives in the database, where malware that specifically targets Sentinel Shield could add itself. Keep the twice-daily scan and the new-administrator alerts on; they report hidden administrators, triggers and new admins independently.

== Settings reference ==

Every setting on Sentinel Shield → Settings, with its key (as used by `wp sentinel settings-get` / `settings-set` and exported settings files), default and recommended value. The same reference, with live values, is on Settings → Documentation.

Malware Lockdown measures are not affected by test mode: once switched on, they are enforced.

<!-- settings-reference:start (generated by bin/readme-settings.php; edit src/SettingsSchema.php instead) -->

= Settings → General & Test Mode =

* **Enable protection** (`general.enabled`; default: On; recommended: On). Master switch. When off, no module runs and nothing is blocked or logged. For emergencies you can also add define( 'SENTINEL_SHIELD_DISABLE', true ); to wp-config.php.
* **Test mode (log only)** (`general.test_mode`; default: On; recommended: Off). Every block decision is recorded as "would block" in the Events log, but the request is allowed and no lockouts are created. Keep this on until you have confirmed IP detection and reviewed the Events log. Turn it off to enforce.
* **End test mode automatically after (hours)** (`general.test_mode_hours`; default: 0; recommended: 24). Range 0–720. Counted from when you save. 0 keeps test mode on until you turn it off.
* **Test mode applies to** (`general.test_mode_scope`; default: All blocks, including manual ones; recommended: All blocks, including manual ones). Choices: "All blocks, including manual ones"; "Automatic blocks only (manual blocks are enforced)". "Automatic blocks only" lets you test lockout thresholds while IPs you blocked by hand stay blocked.
* **Response to blocked visitors** (`general.block_response`; default: 403 Forbidden page (with unlock form for admins); recommended: 403 Forbidden page (with unlock form for admins); per-site on multisite). Choices: "403 Forbidden page (with unlock form for admins)"; "Silent 404 Not Found". A 404 reveals less to attackers but hides the emailed unlock form. Locked-out admins can still use WP-CLI or the wp-config.php constant.
* **Block page message** (`general.block_message`; default: (empty); recommended: your choice; per-site on multisite). Shown on the 403 page. Leave empty for the default text. Plain text only.
* **Keep security events for (days)** (`general.event_retention_days`; default: 30; recommended: 30). Range 1–365. Older events are pruned hourly.
* **Show admin bar indicator** (`general.admin_bar`; default: On; recommended: On; per-site on multisite). Shows blocked requests today and a test mode warning in the toolbar.
* **Delete all data on uninstall** (`general.delete_data_on_uninstall`; default: Off; recommended: Off). When the plugin is deleted, drop its tables and options. Leave off if you might reinstall.

= Settings → IP Detection =

* **Trusted proxy** (`proxy.mode`; default: None: use REMOTE_ADDR only; recommended: None: use REMOTE_ADDR only). Choices: "None: use REMOTE_ADDR only"; "Cloudflare (CF-Connecting-IP, ranges auto-updated weekly)"; "Load balancer / reverse proxy with a header"; "Custom trusted proxy list". Forwarding headers are only read when the request arrives from a trusted proxy IP; otherwise anyone could fake their IP. Pick "None" unless your site sits behind a proxy or CDN. Compare the "Detected IP" above with your real IP before turning off test mode.
* **Client IP header** (`proxy.header`; default: X-Forwarded-For; recommended: X-Forwarded-For). Used by the load balancer and custom presets, e.g. X-Forwarded-For, X-Real-IP, True-Client-IP or Forwarded. Ignored for Cloudflare and None. Your proxy must always set or overwrite this header; if it passes a visitor-supplied value through, visitors can fake their IP. A header the proxy overwrites (such as X-Real-IP from nginx) is safest.
* **Trusted proxy IPs / CIDRs** (`proxy.trusted_cidrs`; default: (empty); recommended: your choice). One per line. IPv4, IPv6 and CIDR ranges allowed; # starts a comment. For the load balancer preset, an empty list trusts private network ranges. For Cloudflare, add any proxy that sits between Cloudflare and this server. A request from a trusted proxy that does not name the visitor (header missing, malformed or listing only proxies) is treated as anonymous and gets none of the proxy's allowlist or server exemptions.
* **This server's own IPs** (`proxy.server_ips`; default: (empty); recommended: your choice). Requests to wp-cron.php from these IPs are never blocked. Loopback and SERVER_ADDR are always included; add your public IP if loopback requests leave and re-enter through it.

= Settings → Lockouts & Unlock =

* **First lockout (minutes)** (`lockout.step1_minutes`; default: 15; recommended: 15). Range 0–525600. Duration of an IP's first lockout. 0 means permanent and makes later steps unused.
* **Second lockout (minutes)** (`lockout.step2_minutes`; default: 60; recommended: 60). Range 0–525600. Used when the IP was locked out once before within the repeat window. 0 = permanent.
* **Third lockout (minutes)** (`lockout.step3_minutes`; default: 1440; recommended: 1440). Range 0–525600. 0 = permanent.
* **Fourth and later lockouts (minutes)** (`lockout.step4_minutes`; default: 0; recommended: 0). Range 0–525600. 0 = permanent block until removed by an admin.
* **Repeat offense window (days)** (`lockout.repeat_window_days`; default: 7; recommended: 7). Range 1–365. Lockouts within this many days escalate to the next step. Older offenses are forgotten.
* **Unlock link lifetime (minutes)** (`unlock.token_ttl_minutes`; default: 30; recommended: 30). Range 5–1440. Emailed unlock links are single-use and expire after this time.
* **Temporary allowlist after unlock (hours)** (`unlock.allow_hours`; default: 24; recommended: 24). Range 1–720. After a successful unlock, the IP is allowlisted for this long so you can fix the cause.
* **Unlock emails per IP per hour** (`unlock.max_requests_per_hour`; default: 3; recommended: 3). Range 1–20. Limits abuse of the unlock form.

= Settings → Login Security =

* **Failed logins per IP before a lockout** (`login.max_failures`; default: 5; recommended: 5). Range 1–100. When one IP fails this many logins within the counting window, it is locked out using the progressive lockout durations on the Lockouts & Unlock tab (15 minutes, then 1 hour, 24 hours and permanent by default), and the login in progress is refused. Wrong passwords, unknown usernames and wrong two-factor codes all count. Allowlisted IPs and this server are never counted. If the Progressive lockouts module is off, logins from the IP are refused until its failures age out.
* **Counting window (minutes)** (`login.window_minutes`; default: 15; recommended: 15). Range 1–1440. Failed logins older than this are no longer counted against an IP or account.
* **Failed logins per account before it is protected** (`login.account_max_failures`; default: 20; recommended: 20). Range 0–1000. Stops attacks spread over many IPs. When one account (by username or email) fails this many logins within the counting window, from any number of IPs, password logins to it are refused except from IPs it logged in from successfully before (the last 10, for 90 days) and allowlisted IPs, until the failures age out. No IP is locked out for this, and the refusal looks the same whether or not the password was right. 0 turns this off.
* **Lock out at once for these usernames** (`login.instant_usernames`; default: (empty); recommended: your choice). Usernames that nobody on this site uses but attackers try first, e.g. "admin, administrator, test, root". Separated by commas, spaces or new lines. A login attempt with one of them locks the IP out after the first failure. A name is ignored while an account with that username or email exists.
* **Do not reveal which usernames exist** (`login.generic_errors`; default: On; recommended: On). WordPress normally says "The username is not registered" or "The password you entered for the username ... is incorrect", which tells attackers which accounts exist. With this on, both become "The username, email address or password is incorrect".
* **Turn off logins over XML-RPC** (`login.disable_xmlrpc`; default: Off; recommended: your choice). XML-RPC (xmlrpc.php) lets programs log in with a username and password and is a favourite brute-force target. With this on, every XML-RPC method that needs a login is refused; pingbacks still work. Leave off if you use the WordPress mobile app with XML-RPC, Jetpack, or a desktop blogging client.
* **Two-factor authentication** (`twofa.required`; default: Optional for everyone; recommended: Required for administrator-level accounts). Choices: "Optional for everyone"; "Required for administrator-level accounts"; "Required for every account". Every user can set up two-factor authentication under Users → Two-Factor Authentication (an authenticator app, codes by email, and backup codes). When it is required, an account without an authenticator app gets a code by email at every login until it sets one up (if email codes are allowed below), and sees a reminder in the dashboard. Administrator-level means the same accounts as the administrator lock. Make sure this site can send email before requiring it.
* **Allow codes by email** (`twofa.email`; default: On; recommended: On). Lets users get an 8-digit login code by email (valid 10 minutes) instead of using an app. Weaker than an app, because anyone who controls the mailbox can log in with the password, but much stronger than a password alone. When off, required accounts without an app cannot log in until one is set up (they are never let in with only a password); the Login Security tab lists them, and it cannot be switched off while your own login needs it.
* **Offer "Trust this browser" for (days)** (`twofa.remember_days`; default: 0; recommended: your choice). Range 0–90. Shows a "Trust this browser" box on the code screen; a trusted browser is not asked for a code again for this many days (the password is still needed). Users can forget all their trusted browsers on their Two-Factor Authentication page, and resetting an account's two-factor forgets them too. 0 asks for a code at every login.

= Settings → Login Location =

* **Login location restriction** (`geo.mode`; default: Off: no location check; recommended: your choice). Choices: "Off: no location check"; "Allow logins only from the countries listed"; "Block logins from the countries listed". Checks the country of every login on wp-login.php, XML-RPC and application passwords (REST API). "Allow only" is the strongest choice when everyone who logs in is in a few known countries. A denied login gets "Logging in from your location is not allowed", whether or not the password was right. Allowlisted IPs and this server are never denied, existing login sessions are not ended, and WP-CLI is not affected.
* **Countries** (`geo.countries`; default: (empty); recommended: your choice). Two-letter ISO country codes separated by commas or spaces, e.g. "US, CA, GB". The full list of codes is below. T1 means the Tor network and is only reported by Cloudflare.
* **Applies to** (`geo.scope`; default: Every account; recommended: Administrator-level accounts only). Choices: "Every account"; "Administrator-level accounts only". "Administrator-level accounts only" protects the accounts that matter most (the same accounts as the administrator lock) while customers and members can log in from anywhere. The account is identified by the submitted username or email; logins naming an account that does not exist are checked only with "Every account".
* **When the country is unknown** (`geo.unknown`; default: Allow the login; recommended: Allow the login). Choices: "Allow the login"; "Deny the login". The country is unknown for private and local addresses, addresses no source knows, and when no country source is set up. Denying is stricter but locks everyone out if the country database is missing.
* **Download the free DB-IP country database** (`geo.dbip`; default: Off; recommended: your choice). Needed unless your site is behind Cloudflare or your server sets a country variable. A 5 MB download from db-ip.com, checked weekly and updated monthly, stored as a 15 MB file in uploads/sentinel-shield. Licensed CC BY 4.0: an "IP Geolocation by DB-IP" link is added to the denial message. DB-IP sees your server's IP when it downloads; nothing about visitors is sent. Switching this off deletes the file.
* **Country from server variable** (`geo.server_var`; default: (empty); recommended: your choice). Name of a server variable holding the visitor's two-letter country code, set by your web server or host, e.g. GEOIP_COUNTRY_CODE (mod_geoip), MM_COUNTRY_CODE (MaxMind module). Used before the DB-IP database. Leave empty if unsure. Names starting with HTTP_ are request headers that visitors can send themselves: they are only used on requests that came through a trusted proxy (IP Detection tab), and that proxy must always set or overwrite the header.

= Settings → Blocklists =

* **Check for list updates** (`feeds.update_hours`; default: Daily; recommended: Daily). Choices: "Twice a day"; "Daily"; "Every 2 days"; "Weekly". How often each enabled list is downloaded. Lists whose provider asks for less frequent downloads are never fetched more often than the provider allows. Unchanged lists are not downloaded again.
* **Spamhaus DROP** (`feeds.lists.spamhaus_drop`; default: Off; recommended: On). Hijacked and criminal-operated networks (IPv4 and IPv6). Very low false-positive rate. Free under the provider's terms, which forbid using the Spamhaus name in marketing. Terms: Free to use (https://www.spamhaus.org/drop/terms/).
* **FireHOL Level 1** (`feeds.lists.firehol_level1`; default: Off; recommended: your choice). Aggregate of Spamhaus DROP, DShield, Feodo and bogon lists, aimed at minimal false positives. Includes DShield data (CC BY-NC-SA), so treat it as non-commercial. Private and reserved ranges in it are skipped automatically. Terms: Non-commercial only (https://iplists.firehol.org/?ipset=firehol_level1).
* **Emerging Threats: compromised hosts** (`feeds.lists.et_compromised`; default: Off; recommended: your choice). Hosts known to be compromised, published by Proofpoint Emerging Threats. Small list. Terms: Check provider terms (https://rules.emergingthreats.net/blockrules/).
* **blocklist.de (all)** (`feeds.lists.blocklist_de`; default: Off; recommended: your choice). IPs reported for SSH, mail, web and login attacks in the last 48 hours by fail2ban users. Large (20,000+ IPs) and fast-changing; dynamic IPs make occasional false positives more likely. Terms: Check provider terms (https://www.blocklist.de/en/export.html).
* **CINS Army** (`feeds.lists.cins_army`; default: Off; recommended: your choice). IPs with poor reputation seen by the Sentinel IPS network. About 15,000 IPs. Terms: Check provider terms (https://cinsscore.com/).
* **IPsum (level 3)** (`feeds.lists.ipsum_3`; default: Off; recommended: your choice). IPs that appear on at least 3 of 30+ public blocklists, rebuilt daily. Public domain (The Unlicense). Large (15,000+ IPs). Terms: Free to use (https://github.com/stamparm/ipsum).
* **DShield top 20 attacking networks** (`feeds.lists.dshield_top`; default: Off; recommended: your choice). The 20 /24 networks with the most attack reports over the last three days, from SANS ISC. Licensed CC BY-NC-SA: non-commercial use only. Terms: Non-commercial only (https://feeds.dshield.org/block.txt).
* **Tor exit nodes** (`feeds.lists.tor_exits`; default: Off; recommended: your choice). Not a list of attackers: blocks everyone using the Tor anonymity network, including legitimate privacy-conscious visitors. Enable only if your site has no Tor audience. Terms: Free to use (https://check.torproject.org/).

= Settings → Malware Lockdown =

* **Disable the plugin and theme file editor** (`lockdown.disable_file_editor`; default: Off; recommended: On). Removes Appearance → Theme File Editor and Plugins → Plugin File Editor for everyone, like DISALLOW_FILE_EDIT. A stolen admin login can then not be used to paste a backdoor into a theme, which is how SC's theme copy is often planted.
* **Block installing and uploading plugins and themes** (`lockdown.block_installs`; default: Off; recommended: your choice). Nobody can add new plugins or themes from the admin (updates still work). SC installs itself as a fake plugin; turn this off briefly when you need to install something.
* **Block PHP in uploads** (`lockdown.block_php_uploads`; default: Off; recommended: On). Rejects uploads whose name or content is a script (including double extensions such as shell.php.jpg and .htaccess/.user.ini files) and, on Apache, adds rules to uploads/.htaccess so PHP files there cannot run. On nginx, add the rule shown on the Malware Lockdown page to your server configuration.
* **Administrator lock** (`lockdown.admin_lock`; default: Off; recommended: On). Only approved administrator accounts keep admin rights; any other account with admin powers (such as one SC writes straight into the database) is treated as having none until approved on the Malware Lockdown page. When first switched on, every administrator shown on the Users screen is approved, hidden ones are not. Recover with: wp sentinel approve-admin <user>. To fix the list in a file instead, define SENTINEL_SHIELD_ADMINS in wp-config.php (see Documentation).
* **Protect Sentinel Shield from being switched off by code** (`lockdown.protect_self`; default: Off; recommended: On). SC deactivates and deletes security plugins. With this on, Sentinel Shield can only be deactivated or deleted by an administrator from the Plugins screen, during an update, or with WP-CLI.
* **Block blockchain command channels** (`lockdown.block_chain_rpc`; default: Off; recommended: On). Stops the site from contacting public Ethereum and BNB Chain RPC gateways and from sending blockchain JSON-RPC calls (eth_call), which SC uses to fetch its commands. Each attempt is logged with the file that made it. Leave off if a plugin on this site legitimately talks to a blockchain.
* **Alert on new administrator accounts** (`lockdown.alert_admin_changes`; default: On; recommended: On). Logs and emails the site admin address whenever an account becomes an administrator through WordPress. Accounts written directly into the database are caught by the scan instead.
* **Email new malware scan findings** (`lockdown.scan_email`; default: On; recommended: On). The scan runs twice a day. New critical findings and warnings are logged; with this on they are also emailed to the site admin address.

= Settings → Modules =

* **Enable: IP blocklist & allowlist enforcement** (`modules.ip_gate.enabled`; default: On; recommended: On). Checks every request against the IP rules early in the WordPress load.
* **Test mode: IP blocklist & allowlist enforcement** (`modules.ip_gate.test_mode`; default: Follow global test mode; recommended: Follow global test mode). Choices: "Follow global test mode"; "Always test mode (log only)"; "Always enforce". Override the global test mode for this module only.
* **Enable: Progressive lockouts** (`modules.lockout.enabled`; default: On; recommended: On). Turns repeat offenses into escalating temporary blocks. Other modules (login protection, 404 blocking, WAF) use it.
* **Test mode: Progressive lockouts** (`modules.lockout.test_mode`; default: Follow global test mode; recommended: Follow global test mode). Choices: "Follow global test mode"; "Always test mode (log only)"; "Always enforce". Override the global test mode for this module only.
* **Enable: Emailed unlock links** (`modules.unlock.enabled`; default: On; recommended: On). Lets a locked-out administrator request a one-time unlock link from the block page.
* **Enable: Blocklist feeds** (`modules.feeds.enabled`; default: On; recommended: On). Blocks IPs listed on the public blocklists chosen on the Blocklists tab and keeps them updated. Your allowlist always wins.
* **Test mode: Blocklist feeds** (`modules.feeds.test_mode`; default: Follow global test mode; recommended: Follow global test mode). Choices: "Follow global test mode"; "Always test mode (log only)"; "Always enforce". Override the global test mode for this module only.
* **Enable: Scheduled task monitor** (`modules.cron_monitor.enabled`; default: On; recommended: On). Records when each WP-Cron task last ran, how long it took and whether it failed, for the Scheduled Tasks page.
* **Enable: Login brute-force protection** (`modules.login_guard.enabled`; default: On; recommended: On). Counts failed logins and locks out IPs or protects accounts as set on the Login Security tab, and hides which usernames exist.
* **Test mode: Login brute-force protection** (`modules.login_guard.test_mode`; default: Follow global test mode; recommended: Follow global test mode). Choices: "Follow global test mode"; "Always test mode (log only)"; "Always enforce". Override the global test mode for this module only.
* **Enable: Two-factor authentication** (`modules.two_factor.enabled`; default: On; recommended: On). Asks for an authenticator app, email or backup code after the password, for accounts that set it up or are required to. Switching this off turns two-factor off for everyone. Not affected by test mode.
* **Enable: Login location restriction** (`modules.geo_login.enabled`; default: On; recommended: On). Allows or blocks logins by country as set on the Login Location tab, and keeps the country database updated.
* **Test mode: Login location restriction** (`modules.geo_login.test_mode`; default: Follow global test mode; recommended: Follow global test mode). Choices: "Follow global test mode"; "Always test mode (log only)"; "Always enforce". Override the global test mode for this module only.
* **Enable: Malware lockdown** (`modules.lockdown.enabled`; default: On; recommended: On). Applies the measures chosen on the Malware Lockdown tab and runs the twice-daily malware scan. Lockdown measures are not affected by test mode.

<!-- settings-reference:end -->

= wp-config.php constants =

* `define( 'SENTINEL_SHIELD_DISABLE', true );` Emergency switch: Sentinel Shield loads nothing. Use it to get back in, fix the cause, then remove the line.
* `define( 'SENTINEL_SHIELD_ADMINS', 'admin#1, jane#7' );` Fixes the approved administrator list in this file and always enforces the administrator lock. See "Fixing the list in wp-config.php" above.
* `define( 'DISALLOW_FILE_EDIT', true );` WordPress's own file editor switch. Stronger than the lockdown setting because it lives in a file instead of the database.
* `define( 'DISABLE_WP_CRON', true );` Only with a real server cron job (the line is shown on the Scheduled Tasks page); otherwise blocklist updates and the malware scan stop.

= Filters =

* `sentinel_shield_allowed_chain_hosts` (array of host names): blockchain gateways a legitimate plugin may still reach while "Block blockchain command channels" is on.

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

Your server downloads the country database from db-ip.com about once a month (with a weekly check whether it changed), so DB-IP sees your server's IP address. Lookups happen on your server; nothing about visitors is sent. The database is licensed CC BY 4.0, so denied logins show an "IP Geolocation by DB-IP" link.

= I cannot install a plugin or theme =

"Block installing and uploading plugins and themes" is on. Untick it on Settings → Malware Lockdown, install, then tick it again, or install with WP-CLI. Updates are never blocked.

= The malware scan found something. Is my site infected? =

Not necessarily: drop-ins, must-use plugins and scheduled tasks are often legitimate. Items marked Critical matched known malware traits and need a close look. If you recognize an item, approve it and you will only be warned again if it changes. If the scan finds SC, follow the cleanup order on the Malware Lockdown page: the order matters, because the copies rebuild each other.

= Why does every visitor have the same IP? =

Your site is behind a proxy and Trusted Proxy is set to None. Pick the matching preset on the IP Detection tab and use the IP resolution simulator on the Tools page to check it.

= What do blocklist providers learn about my site? =

Your server downloads each enabled list directly from its provider (FireHOL and IPsum via GitHub), so the provider sees your server's IP address and when it checks for updates. Sentinel Shield sends a generic "SentinelShield" user agent without your site address, asks whether the list changed before downloading it again, and sends nothing about your visitors.

= Can I use every list on a commercial site? =

No. DShield and FireHOL Level 1 (which includes DShield data) are CC BY-NC-SA, non-commercial only. Spamhaus DROP is free under its terms, which forbid using the Spamhaus name in marketing. For Emerging Threats, blocklist.de and CINS Army, check the provider's terms (linked on the Blocklists tab).

= Does test mode protect anything? =

No. Test mode only records what would have been blocked. Use it to validate settings, then turn it off. Malware Lockdown measures are the exception: they are always enforced once switched on.

== Changelog ==

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

= 0.5.1 =
Security fixes from a code review: trusted proxy fallback, header-based country variables, unlock link revalidation and limits, required two-factor accounts without a method, and concurrent login and code checks. If you require two-factor authentication with email codes off, check the Login Security tab for accounts that can no longer log in.

= 0.5.0 =
Adds login brute-force protection (on by default: 5 failed logins in 15 minutes lock an IP out, allowlisted IPs excepted) and two-factor authentication (optional until you require it on Settings → Login Security).

= 0.4.0 =
Adds the login location (GeoIP) restriction. It is off until you choose a mode and countries on Settings → Login Location.

= 0.3.0 =
Adds the optional SENTINEL_SHIELD_ADMINS wp-config.php constant for a file-based administrator list. Nothing changes unless you define it.

= 0.2.0 =
Adds Malware Lockdown (SC malware scan and opt-in hardening), blocklist feeds, the Scheduled Tasks page and a Documentation tab. All new protections are off until you switch them on.
