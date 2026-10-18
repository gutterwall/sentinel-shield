# Installing and testing Sentinel Shield (Phase 1) without locking yourself out

## 0. Before you start: know your exits

Keep at least one of these ready before you enforce anything:

1. **FTP/SSH access to `wp-config.php`.** Adding `define( 'SENTINEL_SHIELD_DISABLE', true );` above "That's all, stop editing!" disables all blocking.
2. **WP-CLI.** Run `wp sentinel unblock <ip> --allow-hours=24`. WP-CLI is never blocked.
3. **Working email.** The block page can email you a one-time unlock link. Test it in step 5.

Use a **second device** for blocking tests, such as a phone on mobile data, rather than your admin computer.

## 1. Install

```bash
cd wp-content/plugins
unzip sentinel-shield.zip
wp plugin activate sentinel-shield            # multisite: --network
wp sentinel status
```

After activation:

* test mode is **on**, so nothing is blocked
* your IP is in the allowlist (`wp sentinel list --type=allow`)
* four tables exist: `{prefix}sentinel_ip_rules`, `_events`, `_offenses`, `_unlock_tokens`

## 2. Confirm IP detection

Open **Sentinel Shield → Settings → IP Detection**.

* "Detected IP" must equal your public IP (search "what is my IP" from the same device).
* Behind Cloudflare: choose *Cloudflare*. The Detected IP should change from a Cloudflare edge IP to yours.
* Behind a load balancer: choose *Load balancer*, enter the balancer's IPs or CIDRs and the header it sets.
* Fix any warnings shown on that tab before you continue.

Check spoof resistance from a machine **outside** your proxy:

```bash
# Direct to origin, faking a header. The site must NOT treat you as 1.1.1.1:
curl -s -H "X-Forwarded-For: 1.1.1.1" -H "CF-Connecting-IP: 1.1.1.1" https://example.com/ -o /dev/null
wp sentinel events --limit=5
```

Without a server, use the simulator:

```bash
wp sentinel resolve-ip --remote-addr=203.0.113.66 --headers="CF-Connecting-IP: 1.1.1.1" --mode=cloudflare
# ip = 203.0.113.66 (untrusted peer, header ignored)
wp sentinel resolve-ip --remote-addr=173.245.48.10 --headers="CF-Connecting-IP: 198.51.100.4" --mode=cloudflare
# ip = 198.51.100.4
wp sentinel resolve-ip --remote-addr=10.0.0.2 --headers="X-Forwarded-For: 6.6.6.6, 198.51.100.4" --mode=load_balancer
# ip = 198.51.100.4 (the fake 6.6.6.6 is ignored)
```

## 3. Test blocking in test mode

Get your second device's IP (call it `PHONE_IP`).

```bash
wp sentinel block PHONE_IP --reason="test" --minutes=60
wp sentinel check PHONE_IP --uri=/wp-login.php
# Decision: BLOCK ... Test mode: would only be logged.
```

Browse the site from the phone. It should load normally. Then check:

```bash
wp sentinel events --event=would_block
```

You should see a `would_block` entry with the phone's IP and the rule.

## 4. Enforce on the test device only

Option A keeps global test mode on but enforces manual rules:

```bash
wp sentinel settings-set general.test_mode_scope automatic
```

Option B enforces only the IP gate module:

```bash
wp sentinel settings-set modules.ip_gate.test_mode off
```

Reload on the phone. You should see the **403 Access denied** page. Your admin browser is unaffected because it is allowlisted. Confirm with `wp sentinel check YOUR_IP`, which should say ALLOW (allowlist).

Preview the page safely from your admin account: **Tools & Testing → Preview the block page**.

## 5. Test the unlock paths

* **Email link:** Go to Tools & Testing → "Email me a test unlock link" and confirm the email arrives. Then, on the phone's block page, enter your admin email. The link removes the phone's single-IP block and allowlists it for 24 hours (configurable). Using a link twice fails.
* **WP-CLI:** `wp sentinel unblock PHONE_IP`
* **Constant:** Add `define( 'SENTINEL_SHIELD_DISABLE', true );`, reload the phone (it gets through), then remove the line.
* **Rate limit:** Submit the unlock form 4 times within an hour. The 4th submission is refused (default 3/hour).

## 6. Test progressive lockouts

```bash
wp sentinel settings-set lockout.step1_minutes 1
wp sentinel settings-set lockout.step2_minutes 2
wp sentinel lockout 203.0.113.10   # step 1, 60s
wp sentinel lockout 203.0.113.10   # step 2, 120s
wp sentinel lockout 203.0.113.10   # step 3 ...
wp sentinel list --search=203.0.113.10
wp sentinel lockout YOUR_IP        # refused: allowlisted
```

In test mode the output says `TEST MODE: logged only` and no rule is created. Test offenses are stored separately, so they never escalate real lockouts.

## 7. Lockout safety checks

* **Save any settings tab.** Your IP is re-allowlisted if it was missing.
* **Try blocking your own IP or a range containing it** on IP Rules. It is refused.
* **Self-block warning:** `wp sentinel block YOUR_IP` (CLI allows it), then open any Sentinel Shield page. A warning names the rule. Remove it with `wp sentinel unblock YOUR_IP`.
* **Server cron:** `wp sentinel block 127.0.0.1`, then on the server run `curl -s http://127.0.0.1/wp-cron.php -H "Host: example.com"`. It must not get a 403. Then run `wp sentinel check 127.0.0.1 --uri=/wp-cron.php`, which should say PASS (server_cron).

## 8. Go live

```bash
wp sentinel settings-set general.test_mode_scope all
wp sentinel settings-set modules.ip_gate.test_mode inherit
wp sentinel test-mode off
wp sentinel status
```

## 9. Automated tests

```bash
composer install
vendor/bin/phpunit                              # unit: IP parsing, CIDR, range sets, proxy resolution, lockout ladder
bash bin/install-wp-tests.sh wordpress_test root '' 127.0.0.1 latest   # from `wp scaffold plugin-tests`
WP_TESTS_DIR=/tmp/wordpress-tests-lib vendor/bin/phpunit --testsuite integration
vendor/bin/phpcs
```

## Every setting from the command line

```bash
wp sentinel settings-keys            # every key, type, current and recommended value
wp sentinel settings-set <key> <value>
wp sentinel settings-export backup.json
wp sentinel settings-import backup.json
```

## Automated tests and CI

Every push and pull request runs `.github/workflows/ci.yml` (and it runs weekly, so a new WordPress release that breaks something is noticed):

| Job | What it checks |
|---|---|
| Coding standards, docs and build | phpcs (WordPress standards, PHP 8.1 compatibility), the readme settings reference, and a release build (version numbers agree; the zip is kept as an artifact) |
| Unit tests | PHP 8.1, 8.2, 8.3 and 8.4 |
| Integration | The WordPress test suite on the oldest supported WordPress (6.4) and the latest, each as a single site and as multisite, on PHP 8.1 to 8.4 |
| Smoke test | A throwaway site with the plugin active, exercised over HTTP: firewall lockout and unblock, identical login errors, the two-factor step, a required account without any method, the malware scan, WordPress.org checksum verification, and every admin page without PHP errors |

Run the same locally:

```bash
composer install
vendor/bin/phpcs -q && vendor/bin/phpunit                      # coding standards and unit tests

# Integration tests: installs WordPress and its test library (the database is emptied on every run).
bin/install-wp-tests.sh wordpress_test root secret 127.0.0.1 latest /tmp/wp-tests
WP_TESTS_DIR=/tmp/wp-tests/tests-lib vendor/bin/phpunit --testsuite integration
WP_TESTS_DIR=/tmp/wp-tests/tests-lib WP_MULTISITE=1 vendor/bin/phpunit --testsuite integration

# Smoke test against a throwaway site served from 127.0.0.1 (it changes settings and creates users):
bin/smoke-test.sh /path/to/throwaway-site http://127.0.0.1:8099
```

Security fixes come with a regression test (see `tests/Integration/PentestRegressionTest.php` and `ReviewRegressionTest.php`), so a fix cannot quietly come undone.
