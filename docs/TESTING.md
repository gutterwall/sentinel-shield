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

`.github/workflows/ci.yml` runs on every push and pull request; the expensive combinations run nightly (and on demand from the Actions tab).

### Every push and pull request

| Job | What it checks |
|---|---|
| Coding standards, static analysis, audit, secrets and build | phpcs (WordPress standards, PHP 8.1 compatibility); PHPStan level 6 with WordPress and WP-CLI stubs, no baseline; `composer audit`; gitleaks over the whole git history; the settings reference; a release build whose zip every later job tests |
| Unit tests | PHP 8.1, 8.2, 8.3, 8.4 and 8.5 |
| Integration | WordPress 6.4 and latest, single site and multisite, PHP 8.1 to 8.5, MySQL 8 and MariaDB 11.4 and 11.8 (which also exercises the row-lock fallback path in tests that force it) |
| Object cache | The integration tests with Redis as persistent object cache, including the eviction, stale-cache and "cache never answers" tests |
| Coverage | Line coverage with PCOV: unit and integration tests (single site and multisite) in-process, and the early firewall inside the PHP servers its HTTP tests start, reported separately and combined. HTML and Clover reports are kept as artifacts; `bin/coverage-check.php --require=lines` fails the job when any area drops below its floor in `tests/coverage-baseline.json`, when the report is missing or empty, or when a source file of an area has no line data |
| Mutation tests | `bin/mutation-test.php` applies 64 deliberate defects from `tests/mutations.php` (weakened comparisons, expiry checks, capability and nonce checks, replay guards, lock checks, removed verification, ignored deadlines, work continuing after a lost lock, unserialized Cloudflare updates) one at a time; the tests must fail for every one |
| Real site (PHP server) | The smoke test, passkeys in Chrome (registration, login, a passkey synchronized to a second browser profile, a touch-only key under both verification policies, password-manager hints), Plugin Check on the release zip, the 0.8.0 legacy-file upgrade (including an old snapshot written back after the cleanup, as a request still running the old code can do), and the install/deactivate/reactivate/uninstall/upgrade matrix (`bin/lifecycle-test.sh`, upgrades from 0.8.0, 0.8.1, 0.8.2, 0.8.4, 0.8.5 and 0.8.6, checksum-verified) |
| nginx + PHP-FPM, Apache + PHP-FPM | The smoke test; `bin/race-test.php` (ten synchronized requests for one backup code, authenticator code, signed passkey response or identity confirmation: exactly one wins; simultaneous wrong passwords never check more than the limit; six WP-CLI Cloudflare syncs and two confirmation checks started at once against a stand-in API: uploads never overlap, every sync completes, and the state matches the list); `bin/fault-test.sh` (workers killed with SIGKILL at each step of a publication, after a Cloudflare upload and while holding a lock; a full disk); `bin/server-config-test.sh` (the generated files loaded by real nginx and Apache, a blocked address refused, an allowlisted address inside a blocked range let through, and a reload after unblocking or disabling ends enforcement) |

### Nightly

| Job | What it checks |
|---|---|
| Site layouts | `bin/layout-test.sh`: WordPress in a subdirectory and with a moved content folder (full smoke test each), and a multisite subsite on its own domain (firewall, lockouts across domains, two-factor redirects and passkey relying party on the mapped domain) |
| HTTPS behind a proxy | nginx terminates TLS and proxies to the site; the passkey browser test runs over https:// and the pending-login cookie must be `secure` |
| Performance budgets | `bin/bench-site.php` on nginx and Apache with PHP-FPM, compared with `tests/perf-budgets.json` (below) |
| Branch coverage and long fuzzing | Branch coverage with Xdebug for all of `src/` and the early firewall: unit and integration tests (single site and multisite) and the PHP servers the HTTP tests start, merged as a union of branch exits (collected once per run by `tests/coverage/branch-collector.php`; PHPUnit's own path coverage would take hours). Lines and branches are both required (`--require=lines,branches`): a missing report, or a source file of an area that the branch report does not cover, fails the job instead of quietly leaving the floor unchecked. The fuzz and property tests run with 20,000 rounds each |

### Tags

The release zip built by the lint job is the one tested by the later jobs. On a tag, after every job has passed, its build commit is checked against the tag and it gets a GitHub build-provenance attestation (`gh attestation verify sentinel-shield-<version>.zip --repo gutterwall/sentinel-shield`). That zip is what the release publishes.

### Coverage: where it stands

Measured for 0.8.6 (lines on every push; branches nightly, counting each way out of every branch point, merged across runs and the HTTP tests' servers):

| Area | Lines | Branches | Goal |
|---|---|---|---|
| Overall | 82.2% (from 60.6% in 0.8.2) | 56.1% | 90% of lines |
| Authentication (two-factor, passkeys, login) | 86.4% | 63.5% | 95% of branches |
| Authorization (admin actions and pages that change data, plugin protection) | 73.1% | 49.6% | 95% of branches |
| Recovery (unlock, lockouts, safety, tokens) | 85.6% | 57.4% | 95% of branches |
| Policy publication (firewalls, ranges, private folder, locks) | 87.7%; the early firewall itself 91% over HTTP | 64.9% | 95% of branches |

Every source file of every area is in both reports; the required-measurement check found two that were in neither test run (the block page's unlock-form token and the multisite per-site settings page) and both have tests now.

Branch coverage is well short of its goal: many branches are error and edge paths (unreadable files, database errors, unusual proxy headers) that no test reaches yet. The 64 mutants, chosen at the security decisions themselves, are all caught, which says more about those decisions than the percentage does, but closing this gap is the next step.

The goals are engineering targets, not WordPress.org requirements, and even 100% coverage would not prove the code secure; mutation testing is the stronger check that tests actually look at results. Not counted: `uninstall.php` (it deletes the tables the test suite runs on; `bin/lifecycle-test.sh` covers it over a real site), code that runs while the test bootstrap loads WordPress (before coverage starts), and the HTTP-only paths of the smoke, race and crash tests, which are not instrumented. The largest gaps left are the two-factor login screen's HTML (exercised over HTTP), admin page rendering, and the lockdown module's scheduled scans.

### Deadlines, lost locks and concurrent updates

What the tests hold the background work to (`DeadlineTest`, `LostLockTest`, and lost-lock tests in `EarlyGateTest`, `FileIntegrityTest` and `CloudflareContractTest`):

* Housekeeping's budget is a deadline. With no time left nothing starts, not even one batch; a slow database stops it between batches, at most one batch past the deadline, and the later steps wait for the continuation five minutes later, which finishes the job. A policy build that would not fit is handed to its own job. Housekeeping makes no network requests; it only keeps the heartbeat and audit-delivery jobs scheduled.
* Audit delivery caps each request's timeout to the time left and starts no batch with under two seconds left.
* `Mutex::renew()` notices a named lock released with the database connection and a lock row taken over after its lease. A build that lost its lock while writing its range files publishes nothing (no manifest switch, no server files, no state) and leaves the change for the build that holds the lock; an integrity slice saves nothing; an audit batch is not recorded, and the next holder sends the same batch with the same sequence numbers and hashes.
* Cloudflare: while another worker updates the list, nothing reaches the API and nothing changes the state; an upload whose lock was lost leaves the recorded intent, and the next holder uploads again; an answer about an operation the state no longer names, or about the same operation ID on another list, changes nothing.

The in-process tests take a lock away with a second database connection (`tests/Fakes/OtherWorker.php`); the race test runs real processes. Each was checked against the code before these changes: all of them failed there.

### Performance budgets

Typical results on nginx with PHP-FPM (12 workers), uncached pages:

* Added per page: about 2 ms at p50, 1 ms at p95, 0.8 ms CPU, 0.2 MB memory, one database query, no writes.
* A blocked flood is refused by the early firewall (about 21,000 requests a second on one CI-sized machine) and never reaches WordPress; legitimate visitors' p95 stays within a few percent.
* 900 invalid logins from 300 addresses cost 23 password hashes: once an account's limit is reached, attempts are refused without hashing.
* A 20,000-range policy builds in 0.14 s with about 22 MB of memory; rule changes under traffic do not affect visitors' latency.

Counts (queries, writes, hashes, errors) are exact and held to their budgets strictly; time budgets are loose on purpose, since shared CI runners are noisy, and catch only large regressions. For trustworthy timings run `bin/bench-site.php` on a dedicated, idle machine: baseline and plugin runs alternate in random order after a warm-up, and medians are compared.

### Run it locally

```bash
composer install
vendor/bin/phpcs -q && vendor/bin/phpstan analyse && vendor/bin/phpunit

# Integration tests: installs WordPress and its test library (the database is emptied on every run).
bin/install-wp-tests.sh wordpress_test root secret 127.0.0.1 latest /tmp/wp-tests
export WP_TESTS_DIR=/tmp/wp-tests/tests-lib
vendor/bin/phpunit --testsuite integration
WP_MULTISITE=1 vendor/bin/phpunit --testsuite integration

bin/coverage.sh                       # needs PCOV or Xdebug; BRANCHES=1 adds branch coverage (Xdebug)
php bin/mutation-test.php             # about 4 minutes; --list, --only=3,17

# A throwaway site (these change settings, create users and block test addresses):
bin/serve-stack.sh nginx /path/to/site 8098 8443 &     # or apache; or PHP's own server
bin/smoke-test.sh /path/to/site http://127.0.0.1:8098
php bin/race-test.php /path/to/site http://127.0.0.1:8098 10
bin/fault-test.sh /path/to/site http://127.0.0.1:8098
bin/server-config-test.sh /path/to/site
php bin/bench-site.php /path/to/site http://127.0.0.1:8098 --quick
WP_PATH=/path/to/site PASSKEY_USER=admin PASSKEY_PASS=secret bin/passkey-e2e.py http://localhost:8098
bin/lifecycle-test.sh /path/to/site http://127.0.0.1:8098 dist/sentinel-shield-<version>.zip old-release.zip ...
bin/layout-test.sh subdirectory /path/to/wordpress /tmp/layouts 8201 dbname dbuser dbpass 127.0.0.1
```

Fuzz and property tests take `FUZZ_ITERATIONS` and `FUZZ_SEED` (a failure names its seed, so it can be replayed).

Security fixes come with a regression test (see `tests/Integration/PentestRegressionTest.php` and `ReviewRegressionTest.php`), so a fix cannot quietly come undone.

### Not done yet

* An independent review of the WebAuthn and CBOR code by someone other than its authors.
* PHPStan above level 6 (level 8 reports mostly `$wpdb->prepare()` nullability; no real defects were found in a review of its null-dereference findings).
* A Redis restart in the middle of a request (the object-cache job covers eviction, stale entries and an unreachable cache, but does not restart the server mid-run).
* Synchronized passkeys that report a signature counter of 0, as real passkey providers do: Chrome's virtual authenticator always counts, so the test syncs the counter instead.
