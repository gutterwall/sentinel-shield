<?php
/**
 * Declarative settings schema: drives the settings UI, sanitization, import and WP-CLI.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield;

use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Geo\CountryList;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpRangeSet;

defined( 'ABSPATH' ) || exit;

/**
 * Every configurable value is described once here. Translated strings mean this
 * must only be called after `init`.
 */
final class SettingsSchema {

	/**
	 * Settings tabs.
	 *
	 * @return array<string, string>
	 */
	public static function tabs(): array {
		return array(
			'general'      => __( 'General & Test Mode', 'sentinel-shield' ),
			'ip_detection' => __( 'IP Detection', 'sentinel-shield' ),
			'lockout'      => __( 'Lockouts & Unlock', 'sentinel-shield' ),
			'login'        => __( 'Login Security', 'sentinel-shield' ),
			'geo'          => __( 'Login Location', 'sentinel-shield' ),
			'blocklists'   => __( 'Blocklists', 'sentinel-shield' ),
			'server'       => __( 'Server & CDN', 'sentinel-shield' ),
			'alerts'       => __( 'Alerts & Audit Log', 'sentinel-shield' ),
			'lockdown'     => __( 'Malware Lockdown', 'sentinel-shield' ),
			'modules'      => __( 'Modules', 'sentinel-shield' ),
			'docs'         => __( 'Documentation', 'sentinel-shield' ),
		);
	}

	/**
	 * Field definitions.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function fields(): array {
		$test_mode_options = array(
			'inherit' => __( 'Follow global test mode', 'sentinel-shield' ),
			'on'      => __( 'Always test mode (log only)', 'sentinel-shield' ),
			'off'     => __( 'Always enforce', 'sentinel-shield' ),
		);

		$fields = array(
			array(
				'key'         => 'general.enabled',
				'tab'         => 'general',
				'type'        => 'checkbox',
				'label'       => __( 'Enable protection', 'sentinel-shield' ),
				'help'        => __( 'Master switch. When off, no module runs and nothing is blocked or logged. For emergencies you can also add define( \'SENTINEL_SHIELD_DISABLE\', true ); to wp-config.php.', 'sentinel-shield' ),
				'recommended' => true,
			),
			array(
				'key'         => 'general.test_mode',
				'tab'         => 'general',
				'type'        => 'checkbox',
				'label'       => __( 'Test mode (log only)', 'sentinel-shield' ),
				'help'        => __( 'Every block decision is recorded as "would block" in the Events log, but the request is allowed and no lockouts are created. Keep this on until you have confirmed IP detection and reviewed the Events log. Turn it off to enforce.', 'sentinel-shield' ),
				'recommended' => false,
			),
			array(
				'key'         => 'general.test_mode_hours',
				'tab'         => 'general',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 720,
				'label'       => __( 'End test mode automatically after (hours)', 'sentinel-shield' ),
				'help'        => __( 'Counted from when you save. 0 keeps test mode on until you turn it off.', 'sentinel-shield' ),
				'recommended' => 24,
			),
			array(
				'key'         => 'general.test_mode_scope',
				'tab'         => 'general',
				'type'        => 'select',
				'options'     => array(
					'all'       => __( 'All blocks, including manual ones', 'sentinel-shield' ),
					'automatic' => __( 'Automatic blocks only (manual blocks are enforced)', 'sentinel-shield' ),
				),
				'label'       => __( 'Test mode applies to', 'sentinel-shield' ),
				'help'        => __( '"Automatic blocks only" lets you test lockout thresholds while IPs you blocked by hand stay blocked.', 'sentinel-shield' ),
				'recommended' => 'all',
			),
			array(
				'key'         => 'general.block_response',
				'tab'         => 'general',
				'type'        => 'select',
				'options'     => array(
					'403' => __( '403 Forbidden page (with unlock form for admins)', 'sentinel-shield' ),
					'404' => __( 'Silent 404 Not Found', 'sentinel-shield' ),
				),
				'label'       => __( 'Response to blocked visitors', 'sentinel-shield' ),
				'help'        => __( 'A 404 reveals less to attackers but hides the emailed unlock form. Locked-out admins can still use WP-CLI or the wp-config.php constant.', 'sentinel-shield' ),
				'recommended' => '403',
				'overridable' => true,
			),
			array(
				'key'         => 'general.block_message',
				'tab'         => 'general',
				'type'        => 'textarea',
				'label'       => __( 'Block page message', 'sentinel-shield' ),
				'help'        => __( 'Shown on the 403 page. Leave empty for the default text. Plain text only.', 'sentinel-shield' ),
				'recommended' => null,
				'overridable' => true,
			),
			array(
				'key'         => 'general.event_retention_days',
				'tab'         => 'general',
				'type'        => 'number',
				'min'         => 1,
				'max'         => 365,
				'label'       => __( 'Keep security events for (days)', 'sentinel-shield' ),
				'help'        => __( 'Older events are pruned hourly.', 'sentinel-shield' ),
				'recommended' => 30,
			),
			array(
				'key'         => 'general.admin_bar',
				'tab'         => 'general',
				'type'        => 'checkbox',
				'label'       => __( 'Show admin bar indicator', 'sentinel-shield' ),
				'help'        => __( 'Shows blocked requests today and a test mode warning in the toolbar.', 'sentinel-shield' ),
				'recommended' => true,
				'overridable' => true,
			),
			array(
				'key'         => 'general.delete_data_on_uninstall',
				'tab'         => 'general',
				'type'        => 'checkbox',
				'label'       => __( 'Delete all data on uninstall', 'sentinel-shield' ),
				'help'        => __( 'When the plugin is deleted, drop its tables and options. Leave off if you might reinstall.', 'sentinel-shield' ),
				'recommended' => false,
			),
			array(
				'key'         => 'proxy.mode',
				'tab'         => 'ip_detection',
				'type'        => 'select',
				'options'     => array(
					'none'          => __( 'None: use REMOTE_ADDR only', 'sentinel-shield' ),
					'cloudflare'    => __( 'Cloudflare (CF-Connecting-IP, ranges auto-updated weekly)', 'sentinel-shield' ),
					'load_balancer' => __( 'Load balancer / reverse proxy with a header', 'sentinel-shield' ),
					'custom'        => __( 'Custom trusted proxy list', 'sentinel-shield' ),
				),
				'label'       => __( 'Trusted proxy', 'sentinel-shield' ),
				'help'        => __( 'Forwarding headers are only read when the request arrives from a trusted proxy IP; otherwise anyone could fake their IP. Pick "None" unless your site sits behind a proxy or CDN. Compare the "Detected IP" above with your real IP before turning off test mode.', 'sentinel-shield' ),
				'recommended' => 'none',
			),
			array(
				'key'         => 'proxy.header',
				'tab'         => 'ip_detection',
				'type'        => 'header',
				'label'       => __( 'Client IP header', 'sentinel-shield' ),
				'help'        => __( 'Used by the load balancer and custom presets, e.g. X-Forwarded-For, X-Real-IP, True-Client-IP or Forwarded. Ignored for Cloudflare and None. Your proxy must always set or overwrite this header; if it passes a visitor-supplied value through, visitors can fake their IP. A header the proxy overwrites (such as X-Real-IP from nginx) is safest.', 'sentinel-shield' ),
				'recommended' => 'X-Forwarded-For',
			),
			array(
				'key'         => 'proxy.trusted_cidrs',
				'tab'         => 'ip_detection',
				'type'        => 'cidr_list',
				// Trusting 0.0.0.0/0 (or similar) would let any visitor choose their IP.
				'min_prefix'  => array(
					4 => 8,
					6 => 16,
				),
				'label'       => __( 'Trusted proxy IPs / CIDRs', 'sentinel-shield' ),
				'help'        => __( 'One per line. IPv4, IPv6 and CIDR ranges allowed; # starts a comment. For the load balancer preset, an empty list trusts private network ranges. For Cloudflare, add any proxy that sits between Cloudflare and this server. A request from a trusted proxy that does not name the visitor (header missing, malformed or listing only proxies) is treated as anonymous and gets none of the proxy\'s allowlist or server exemptions.', 'sentinel-shield' ),
				'recommended' => null,
			),
			array(
				'key'         => 'proxy.server_ips',
				'tab'         => 'ip_detection',
				'type'        => 'cidr_list',
				'label'       => __( "This server's own IPs", 'sentinel-shield' ),
				'help'        => __( 'Requests to wp-cron.php from these IPs are never blocked. Loopback and SERVER_ADDR are always included; add your public IP if loopback requests leave and re-enter through it.', 'sentinel-shield' ),
				'recommended' => null,
			),
			array(
				'key'         => 'lockout.step1_minutes',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 525600,
				'label'       => __( 'First lockout (minutes)', 'sentinel-shield' ),
				'help'        => __( 'Duration of an IP\'s first lockout. 0 means permanent and makes later steps unused.', 'sentinel-shield' ),
				'recommended' => 15,
			),
			array(
				'key'         => 'lockout.step2_minutes',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 525600,
				'label'       => __( 'Second lockout (minutes)', 'sentinel-shield' ),
				'help'        => __( 'Used when the IP was locked out once before within the repeat window. 0 = permanent.', 'sentinel-shield' ),
				'recommended' => 60,
			),
			array(
				'key'         => 'lockout.step3_minutes',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 525600,
				'label'       => __( 'Third lockout (minutes)', 'sentinel-shield' ),
				'help'        => __( '0 = permanent.', 'sentinel-shield' ),
				'recommended' => 1440,
			),
			array(
				'key'         => 'lockout.step4_minutes',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 525600,
				'label'       => __( 'Fourth and later lockouts (minutes)', 'sentinel-shield' ),
				'help'        => __( '0 = permanent block until removed by an admin.', 'sentinel-shield' ),
				'recommended' => 0,
			),
			array(
				'key'         => 'lockout.repeat_window_days',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 1,
				'max'         => 365,
				'label'       => __( 'Repeat offense window (days)', 'sentinel-shield' ),
				'help'        => __( 'Lockouts within this many days escalate to the next step. Older offenses are forgotten.', 'sentinel-shield' ),
				'recommended' => 7,
			),
			array(
				'key'         => 'unlock.token_ttl_minutes',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 5,
				'max'         => 1440,
				'label'       => __( 'Unlock link lifetime (minutes)', 'sentinel-shield' ),
				'help'        => __( 'Emailed unlock links are single-use and expire after this time.', 'sentinel-shield' ),
				'recommended' => 30,
			),
			array(
				'key'         => 'unlock.allow_hours',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 1,
				'max'         => 720,
				'label'       => __( 'Temporary allowlist after unlock (hours)', 'sentinel-shield' ),
				'help'        => __( 'After a successful unlock, the IP is allowlisted for this long so you can fix the cause.', 'sentinel-shield' ),
				'recommended' => 24,
			),
			array(
				'key'         => 'unlock.admin_allow_days',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 0,
				'max'         => 365,
				'label'       => __( 'Keep automatic administrator allowlist entries for (days)', 'sentinel-shield' ),
				'help'        => __( 'When an administrator saves settings, their IP is allowlisted so they cannot lock themselves out. The entry lasts this many days and is renewed whenever an administrator uses the dashboard from that IP, so only IPs nobody has used for that long drop off. Home and mobile IPs change and get reassigned to other people, so a permanent entry could end up trusting a stranger. 0 keeps the entries forever (the behavior before 0.6.0). Automatic entries keep the IP from being blocked but do not exempt it from login limits or login location rules (everyone at a shared address would be exempt too); add an address yourself on the IP Rules page for that. Entries you add yourself are never changed.', 'sentinel-shield' ),
				'recommended' => 30,
			),
			array(
				'key'         => 'unlock.max_requests_per_hour',
				'tab'         => 'lockout',
				'type'        => 'number',
				'min'         => 1,
				'max'         => 20,
				'label'       => __( 'Unlock emails per IP per hour', 'sentinel-shield' ),
				'help'        => __( 'Limits abuse of the unlock form.', 'sentinel-shield' ),
				'recommended' => 3,
			),
		);

		$fields[] = array(
			'key'         => 'login.max_failures',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 1,
			'max'         => 100,
			'label'       => __( 'Failed logins per IP before a lockout', 'sentinel-shield' ),
			'help'        => __( 'When one IP fails this many logins within the counting window, it is locked out using the progressive lockout durations on the Lockouts & Unlock tab (15 minutes, then 1 hour, 24 hours and permanent by default), and the login in progress is refused. Wrong passwords, unknown usernames and wrong two-factor codes all count. Allowlisted IPs and this server are never counted. If the Progressive lockouts module is off, logins from the IP are refused until its failures age out.', 'sentinel-shield' ),
			'recommended' => 5,
		);
		$fields[] = array(
			'key'         => 'login.window_minutes',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 1,
			'max'         => 1440,
			'label'       => __( 'Counting window (minutes)', 'sentinel-shield' ),
			'help'        => __( 'Failed logins older than this are no longer counted against an IP or account.', 'sentinel-shield' ),
			'recommended' => 15,
		);
		$fields[] = array(
			'key'         => 'login.account_max_failures',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 0,
			'max'         => 1000,
			'label'       => __( 'Failed logins per account before it is protected', 'sentinel-shield' ),
			'help'        => __( 'Stops attacks spread over many IPs. When one account (by username or email) fails this many logins within the counting window, from any number of IPs, password logins to it are refused except from IPs it logged in from successfully before (the last 10, for 90 days) and allowlisted IPs, until the failures age out. No IP is locked out for this, and the refusal looks the same whether or not the password was right. 0 turns this off.', 'sentinel-shield' ),
			'recommended' => 20,
		);
		$fields[] = array(
			'key'         => 'login.instant_usernames',
			'tab'         => 'login',
			'type'        => 'textarea',
			'label'       => __( 'Lock out at once for these usernames', 'sentinel-shield' ),
			'help'        => __( 'Usernames that nobody on this site uses but attackers try first, e.g. "admin, administrator, test, root". Separated by commas, spaces or new lines. A login attempt with one of them locks the IP out after the first failure. A name is ignored while an account with that username or email exists.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'login.generic_errors',
			'tab'         => 'login',
			'type'        => 'checkbox',
			'label'       => __( 'Do not reveal which usernames exist', 'sentinel-shield' ),
			'help'        => __( 'WordPress normally says "The username is not registered" or "The password you entered for the username ... is incorrect", which tells attackers which accounts exist. With this on, both become "The username, email address or password is incorrect".', 'sentinel-shield' ),
			'recommended' => true,
		);
		$fields[] = array(
			'key'         => 'login.disable_xmlrpc',
			'tab'         => 'login',
			'type'        => 'checkbox',
			'label'       => __( 'Turn off logins over XML-RPC', 'sentinel-shield' ),
			'help'        => __( 'XML-RPC (xmlrpc.php) lets programs log in with a username and password and is a favourite brute-force target. With this on, every XML-RPC method that needs a login is refused; pingbacks still work. Leave off if you use the WordPress mobile app with XML-RPC, Jetpack, or a desktop blogging client.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'login.app_passwords',
			'tab'         => 'login',
			'type'        => 'select',
			'options'     => array(
				'all'            => __( 'Allowed for every account (WordPress default)', 'sentinel-shield' ),
				'non_privileged' => __( 'Not for administrator-level accounts', 'sentinel-shield' ),
				'off'            => __( 'Not allowed for anyone', 'sentinel-shield' ),
			),
			'label'       => __( 'Application passwords', 'sentinel-shield' ),
			'help'        => __( 'Application passwords let programs (the mobile app, integrations, scripts) use the REST API and XML-RPC. They skip two-factor authentication by design, so a forgotten one on an administrator account is a standing way in. Blocking them for administrator-level accounts is a good default when no integration needs one; existing ones then stop working and cannot be created.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'login.app_password_max_days',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 0,
			'max'         => 3650,
			'label'       => __( 'Application passwords expire after (days)', 'sentinel-shield' ),
			'help'        => __( 'Application passwords older than this stop working; the owner creates a new one. 0 = never expire.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'login.app_password_unused_days',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 0,
			'max'         => 3650,
			'label'       => __( 'Retire application passwords unused for (days)', 'sentinel-shield' ),
			'help'        => __( 'An application password nobody used for this long stops working, so forgotten integrations do not stay open. 0 = keep them.', 'sentinel-shield' ),
			'recommended' => 180,
		);
		$fields[] = array(
			'key'         => 'twofa.required',
			'tab'         => 'login',
			'type'        => 'select',
			'options'     => array(
				'none'       => __( 'Optional for everyone', 'sentinel-shield' ),
				'privileged' => __( 'Required for administrator-level accounts', 'sentinel-shield' ),
				'all'        => __( 'Required for every account', 'sentinel-shield' ),
			),
			'label'       => __( 'Two-factor authentication', 'sentinel-shield' ),
			'help'        => __( 'Every user can set up two-factor authentication under Users → Two-Factor Authentication (an authenticator app, codes by email, and backup codes). When it is required, an account without an authenticator app gets a code by email at every login until it sets one up (if email codes are allowed below), and sees a reminder in the dashboard. Administrator-level means the same accounts as the administrator lock. Make sure this site can send email before requiring it.', 'sentinel-shield' ),
			'recommended' => 'privileged',
		);
		$fields[] = array(
			'key'         => 'twofa.email',
			'tab'         => 'login',
			'type'        => 'checkbox',
			'label'       => __( 'Allow codes by email', 'sentinel-shield' ),
			'help'        => __( 'Lets users get an 8-digit login code by email (valid 10 minutes) instead of using an app. Weaker than an app, because anyone who controls the mailbox can log in with the password, but much stronger than a password alone. When off, required accounts without an app cannot log in until one is set up (they are never let in with only a password); the Login Security tab lists them, and it cannot be switched off while your own login needs it.', 'sentinel-shield' ),
			'recommended' => true,
		);
		$fields[] = array(
			'key'         => 'twofa.remember_days',
			'tab'         => 'login',
			'type'        => 'number',
			'min'         => 0,
			'max'         => 90,
			'label'       => __( 'Offer "Trust this browser" for (days)', 'sentinel-shield' ),
			'help'        => __( 'Shows a "Trust this browser" box on the code screen; a trusted browser is not asked for a code again for this many days (the password is still needed). Users can forget all their trusted browsers on their Two-Factor Authentication page, and resetting an account\'s two-factor forgets them too. 0 asks for a code at every login.', 'sentinel-shield' ),
			'recommended' => null,
		);

		$fields[] = array(
			'key'         => 'geo.mode',
			'tab'         => 'geo',
			'type'        => 'select',
			'options'     => array(
				'off'   => __( 'Off: no location check', 'sentinel-shield' ),
				'allow' => __( 'Allow logins only from the countries listed', 'sentinel-shield' ),
				'block' => __( 'Block logins from the countries listed', 'sentinel-shield' ),
			),
			'label'       => __( 'Login location restriction', 'sentinel-shield' ),
			'help'        => __( 'Checks the country of every login on wp-login.php, XML-RPC and application passwords (REST API). "Allow only" is the strongest choice when everyone who logs in is in a few known countries. A denied login gets "Logging in from your location is not allowed", whether or not the password was right. Allowlisted IPs and this server are never denied, existing login sessions are not ended, and WP-CLI is not affected.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'geo.countries',
			'tab'         => 'geo',
			'type'        => 'country_list',
			'label'       => __( 'Countries', 'sentinel-shield' ),
			'help'        => __( 'Two-letter ISO country codes separated by commas or spaces, e.g. "US, CA, GB". The full list of codes is below. T1 means the Tor network and is only reported by Cloudflare.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'geo.scope',
			'tab'         => 'geo',
			'type'        => 'select',
			'options'     => array(
				'all'        => __( 'Every account', 'sentinel-shield' ),
				'privileged' => __( 'Administrator-level accounts only', 'sentinel-shield' ),
			),
			'label'       => __( 'Applies to', 'sentinel-shield' ),
			'help'        => __( '"Administrator-level accounts only" protects the accounts that matter most (the same accounts as the administrator lock) while customers and members can log in from anywhere. The account is identified by the submitted username or email; logins naming an account that does not exist are checked only with "Every account".', 'sentinel-shield' ),
			'recommended' => 'privileged',
		);
		$fields[] = array(
			'key'         => 'geo.unknown',
			'tab'         => 'geo',
			'type'        => 'select',
			'options'     => array(
				'allow' => __( 'Allow the login', 'sentinel-shield' ),
				'deny'  => __( 'Deny the login', 'sentinel-shield' ),
			),
			'label'       => __( 'When the country is unknown', 'sentinel-shield' ),
			'help'        => __( 'The country is unknown for private and local addresses, addresses no source knows, and when no country source is set up. Denying is stricter but locks everyone out if the country database is missing.', 'sentinel-shield' ),
			'recommended' => 'allow',
		);
		$fields[] = array(
			'key'         => 'geo.dbip',
			'tab'         => 'geo',
			'type'        => 'checkbox',
			'label'       => __( 'Download the free DB-IP country database (shows a credit link to db-ip.com on denied logins)', 'sentinel-shield' ),
			'help'        => __( 'Needed unless your site is behind Cloudflare or your server sets a country variable. A 5 MB download from db-ip.com, checked weekly and updated monthly, stored as a 15 MB file in uploads/sentinel-shield. The database is licensed CC BY 4.0, which requires crediting DB-IP: by switching this on you agree that a visitor whose login is refused because of a DB-IP lookup sees "IP Geolocation by DB-IP" linking to db-ip.com under the refusal message. That is the only public place the credit appears; it is also shown in the admin. DB-IP sees your server\'s IP when it downloads; nothing about visitors is sent. Switching this off deletes the file and the credit.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'geo.server_var',
			'tab'         => 'geo',
			'type'        => 'server_var',
			'label'       => __( 'Country from server variable', 'sentinel-shield' ),
			'help'        => __( 'Name of a server variable holding the visitor\'s two-letter country code, set by your web server or host, e.g. GEOIP_COUNTRY_CODE (mod_geoip), MM_COUNTRY_CODE (MaxMind module). Used before the DB-IP database. Leave empty if unsure. Names starting with HTTP_ are request headers that visitors can send themselves: they are only used on requests that came through a trusted proxy (IP Detection tab), and that proxy must always set or overwrite the header.', 'sentinel-shield' ),
			'recommended' => null,
		);

		$fields[] = array(
			'key'         => 'feeds.update_hours',
			'tab'         => 'blocklists',
			'type'        => 'select',
			'options'     => array(
				'12'  => __( 'Twice a day', 'sentinel-shield' ),
				'24'  => __( 'Daily', 'sentinel-shield' ),
				'48'  => __( 'Every 2 days', 'sentinel-shield' ),
				'168' => __( 'Weekly', 'sentinel-shield' ),
			),
			'label'       => __( 'Check for list updates', 'sentinel-shield' ),
			'help'        => __( 'How often each enabled list is downloaded. Lists whose provider asks for less frequent downloads are never fetched more often than the provider allows. Unchanged lists are not downloaded again.', 'sentinel-shield' ),
			'recommended' => '24',
		);
		foreach ( FeedCatalog::all() as $slug => $feed ) {
			$fields[] = array(
				'key'         => "feeds.lists.$slug",
				'tab'         => 'blocklists',
				'type'        => 'checkbox',
				'label'       => (string) $feed['name'],
				/* translators: 1: description, 2: terms summary, 3: terms URL. */
				'help'        => sprintf( __( '%1$s Terms: %2$s (%3$s).', 'sentinel-shield' ), (string) $feed['about'], FeedCatalog::terms_label( (string) $feed['terms'] ), (string) $feed['terms_url'] ),
				'recommended' => 'spamhaus_drop' === $slug ? true : null,
			);
		}

		$fields[] = array(
			'key'         => 'audit.webhook_url',
			'tab'         => 'alerts',
			'type'        => 'url',
			'label'       => __( 'Send events to a webhook', 'sentinel-shield' ),
			'help'        => __( 'An https:// address that receives security events as JSON as they happen (a log service, SIEM, or your own script). Each request is signed with HMAC-SHA256 using the secret shown below, and each event is chained to the previous one by a hash, so missing or altered events show. Someone who takes over the site can empty its database; events already sent stay safe. Failed deliveries are retried with increasing delays.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'audit.scope',
			'tab'         => 'alerts',
			'type'        => 'select',
			'options'     => array(
				'security' => __( 'Security events (everything except routine blocked requests)', 'sentinel-shield' ),
				'all'      => __( 'All events, including every blocked request', 'sentinel-shield' ),
			),
			'label'       => __( 'Events to send', 'sentinel-shield' ),
			'help'        => __( 'Blocked requests can be thousands an hour during an attack; leave them out unless your receiver expects that volume.', 'sentinel-shield' ),
			'recommended' => 'security',
		);
		$fields[] = array(
			'key'         => 'audit.syslog',
			'tab'         => 'alerts',
			'type'        => 'checkbox',
			'label'       => __( 'Also write events to the system log', 'sentinel-shield' ),
			'help'        => __( 'Writes each event as a line of JSON to syslog (facility auth, tag sentinel-shield), so the server can forward it (for example rsyslog to a central log server) or fail2ban can act on it.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'audit.heartbeat_url',
			'tab'         => 'alerts',
			'type'        => 'url',
			'label'       => __( 'Heartbeat URL', 'sentinel-shield' ),
			'help'        => __( 'Pinged every hour by the maintenance job, for a monitoring service that alerts you when the pings stop (for example healthchecks.io or Uptime Kuma push monitors). Silence means the site is down, Sentinel Shield was switched off, or scheduled jobs stopped: all things an attacker might cause.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'firewall.early_gate',
			'tab'         => 'server',
			'type'        => 'select',
			'options'     => array(
				'off'       => __( 'Off', 'sentinel-shield' ),
				'mu_plugin' => __( 'Before other plugins (must-use plugin, set up automatically)', 'sentinel-shield' ),
				'prepend'   => __( 'Before WordPress (auto_prepend_file, set up in your server configuration)', 'sentinel-shield' ),
			),
			'label'       => __( 'Early firewall', 'sentinel-shield' ),
			'help'        => __( 'Blocks IPs on your blocklist (manual rules, lockouts and enabled blocklist feeds) before WordPress or other plugins load, so floods from blocked IPs cost almost nothing. "Before other plugins" installs a small must-use plugin. "Before WordPress" also covers PHP files outside WordPress, and needs one line in php.ini, .user.ini or the web server configuration (shown below). Allowlisted IPs, this server\'s cron requests and unlock links always pass; anything doubtful is left to the normal firewall, so it never blocks more than WordPress would.', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'firewall.server_files',
			'tab'         => 'server',
			'type'        => 'checkbox',
			'label'       => __( 'Write nginx and Apache blocklist files', 'sentinel-shield' ),
			'help'        => __( 'Keeps nginx-deny.conf and apache-deny.conf in uploads/sentinel-shield up to date with your enforced block rules (manual rules and lockouts), so the web server can refuse those IPs before PHP runs, including for images and other static files. Include the file in your server configuration; nginx needs a reload to pick up changes (for example from a cron job).', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'cloudflare.sync',
			'tab'         => 'server',
			'type'        => 'checkbox',
			'label'       => __( 'Sync blocked IPs to a Cloudflare IP list', 'sentinel-shield' ),
			'help'        => __( 'Replaces the items of one Cloudflare account IP list with your effective block policy whenever it changes: enforced block rules minus your allowlist, exactly what WordPress blocks (at most 10,000). Switching this off, switching protection off, or deactivating the plugin empties the list. Add a WAF custom rule in Cloudflare that blocks requests whose IP is in the list, and blocked IPs never reach your server. Needs the account ID, the list ID and an API token with "Account Filter Lists: Edit" (entered below).', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'cloudflare.ipv6',
			'tab'         => 'server',
			'type'        => 'select',
			'options'     => array(
				'skip'   => __( 'Leave single IPv6 addresses out (they stay blocked by WordPress)', 'sentinel-shield' ),
				'expand' => __( 'Widen single IPv6 addresses to their /64', 'sentinel-shield' ),
			),
			'label'       => __( 'Single IPv6 addresses at Cloudflare', 'sentinel-shield' ),
			'help'        => __( 'Cloudflare lists accept IPv6 ranges only up to /64. Widening blocks the whole /64 (usually one customer\'s network, but it can include other people); a /64 that contains an allowlisted address is never widened. The Server & CDN tab shows how many entries were left out or widened.', 'sentinel-shield' ),
			'recommended' => 'skip',
		);
		$fields[] = array(
			'key'         => 'cloudflare.account_id',
			'tab'         => 'server',
			'type'        => 'hex_id',
			'label'       => __( 'Cloudflare account ID', 'sentinel-shield' ),
			'help'        => __( 'Shown in the Cloudflare dashboard on the account\'s overview page (32 characters).', 'sentinel-shield' ),
			'recommended' => null,
		);
		$fields[] = array(
			'key'         => 'cloudflare.list_id',
			'tab'         => 'server',
			'type'        => 'hex_id',
			'label'       => __( 'Cloudflare IP list ID', 'sentinel-shield' ),
			'help'        => __( 'Create a list of type IP under Manage Account → Configurations → Lists; its ID is the last part of the list\'s address in the dashboard (32 characters). Sentinel Shield replaces all items of this list, so use a list of its own.', 'sentinel-shield' ),
			'recommended' => null,
		);

		$lockdown = array(
			'disable_file_editor' => array(
				__( 'Disable the plugin and theme file editor', 'sentinel-shield' ),
				__( 'Removes Appearance → Theme File Editor and Plugins → Plugin File Editor for everyone, like DISALLOW_FILE_EDIT. A stolen admin login can then not be used to paste a backdoor into a theme, which is how SC\'s theme copy is often planted.', 'sentinel-shield' ),
				true,
			),
			'block_installs'      => array(
				__( 'Block installing and uploading plugins and themes', 'sentinel-shield' ),
				__( 'Nobody can add new plugins or themes from the admin (updates still work). SC installs itself as a fake plugin; turn this off briefly when you need to install something.', 'sentinel-shield' ),
				null,
			),
			'block_php_uploads'   => array(
				__( 'Block PHP in uploads', 'sentinel-shield' ),
				__( 'Rejects uploads whose name or content is a script (including double extensions such as shell.php.jpg and .htaccess/.user.ini files) and, on Apache, adds rules to uploads/.htaccess so PHP files there cannot run. On nginx, add the rule shown on the Malware Lockdown page to your server configuration.', 'sentinel-shield' ),
				true,
			),
			'admin_lock'          => array(
				__( 'Administrator lock', 'sentinel-shield' ),
				__( 'Only approved administrator accounts keep admin rights; any other account with admin powers (such as one SC writes straight into the database) is treated as having none until approved on the Malware Lockdown page. When first switched on, every administrator shown on the Users screen is approved, hidden ones are not. Recover with: wp sentinel approve-admin <user>. To fix the list in a file instead, define SENTINEL_SHIELD_ADMINS in wp-config.php (see Documentation).', 'sentinel-shield' ),
				true,
			),
			'protect_self'        => array(
				__( 'Protect Sentinel Shield from being switched off by code', 'sentinel-shield' ),
				__( 'SC deactivates and deletes security plugins. With this on, Sentinel Shield can only be deactivated or deleted by an administrator from the Plugins screen, during an update, or with WP-CLI.', 'sentinel-shield' ),
				true,
			),
			'block_chain_rpc'     => array(
				__( 'Block blockchain command channels', 'sentinel-shield' ),
				__( 'Stops the site from contacting public Ethereum and BNB Chain RPC gateways and from sending blockchain JSON-RPC calls (eth_call), which SC uses to fetch its commands. Each attempt is logged with the file that made it. Leave off if a plugin on this site legitimately talks to a blockchain.', 'sentinel-shield' ),
				true,
			),
			'alert_admin_changes' => array(
				__( 'Alert on new administrator accounts', 'sentinel-shield' ),
				__( 'Logs and emails the site admin address whenever an account becomes an administrator through WordPress. Accounts written directly into the database are caught by the scan instead.', 'sentinel-shield' ),
				true,
			),
			'scan_email'          => array(
				__( 'Email new malware scan findings', 'sentinel-shield' ),
				__( 'The scan runs twice a day. New critical findings and warnings are logged; with this on they are also emailed to the site admin address. The same applies to the file integrity check.', 'sentinel-shield' ),
				true,
			),
			'integrity_checks'    => array(
				__( 'Verify core and plugin files against WordPress.org checksums', 'sentinel-shield' ),
				__( 'Once a day, every WordPress core file and every file of plugins hosted on WordPress.org is compared with the hash WordPress.org publishes for the installed version, and core folders are checked for files no release contains. Changed or added files are reported on the Malware Lockdown page. Large sites are checked in slices over several minutes. The site asks WordPress.org for the checksums of your WordPress and plugin versions (as update checks already do); nothing about visitors is sent. Themes, premium plugins and single-file plugins cannot be verified this way and are listed as such.', 'sentinel-shield' ),
				true,
			),
		);
		if ( defined( 'SENTINEL_SHIELD_ADMINS' ) ) {
			$lockdown['admin_lock'][1] .= ' ' . __( 'On this site the list is fixed by SENTINEL_SHIELD_ADMINS in wp-config.php, so the lock is always enforced and this checkbox has no effect.', 'sentinel-shield' );
		}
		foreach ( $lockdown as $key => $meta ) {
			$fields[] = array(
				'key'         => "lockdown.$key",
				'tab'         => 'lockdown',
				'type'        => 'checkbox',
				'label'       => $meta[0],
				'help'        => $meta[1],
				'recommended' => $meta[2],
			);
		}

		$modules = array(
			'ip_gate'      => array(
				__( 'IP blocklist & allowlist enforcement', 'sentinel-shield' ),
				__( 'Checks every request against the IP rules early in the WordPress load.', 'sentinel-shield' ),
				true,
			),
			'lockout'      => array(
				__( 'Progressive lockouts', 'sentinel-shield' ),
				__( 'Turns repeat offenses into escalating temporary blocks. Other modules (login protection, 404 blocking, WAF) use it.', 'sentinel-shield' ),
				true,
			),
			'unlock'       => array(
				__( 'Emailed unlock links', 'sentinel-shield' ),
				__( 'Lets a locked-out administrator request a one-time unlock link from the block page.', 'sentinel-shield' ),
				false,
			),
			'feeds'        => array(
				__( 'Blocklist feeds', 'sentinel-shield' ),
				__( 'Blocks IPs listed on the public blocklists chosen on the Blocklists tab and keeps them updated. Your allowlist always wins.', 'sentinel-shield' ),
				true,
			),
			'cron_monitor' => array(
				__( 'Scheduled task monitor', 'sentinel-shield' ),
				__( 'Records when each WP-Cron task last ran, how long it took and whether it failed, for the Scheduled Tasks page.', 'sentinel-shield' ),
				false,
			),
			'login_guard'  => array(
				__( 'Login brute-force protection', 'sentinel-shield' ),
				__( 'Counts failed logins and locks out IPs or protects accounts as set on the Login Security tab, and hides which usernames exist.', 'sentinel-shield' ),
				true,
			),
			'two_factor'   => array(
				__( 'Two-factor authentication', 'sentinel-shield' ),
				__( 'Asks for an authenticator app, email or backup code after the password, for accounts that set it up or are required to. Switching this off turns two-factor off for everyone. Not affected by test mode.', 'sentinel-shield' ),
				false,
			),
			'geo_login'    => array(
				__( 'Login location restriction', 'sentinel-shield' ),
				__( 'Allows or blocks logins by country as set on the Login Location tab, and keeps the country database updated.', 'sentinel-shield' ),
				true,
			),
			'lockdown'     => array(
				__( 'Malware lockdown', 'sentinel-shield' ),
				__( 'Applies the measures chosen on the Malware Lockdown tab and runs the twice-daily malware scan. Lockdown measures are not affected by test mode.', 'sentinel-shield' ),
				false,
			),
		);
		foreach ( $modules as $slug => $meta ) {
			$fields[] = array(
				'key'         => "modules.$slug.enabled",
				'tab'         => 'modules',
				'type'        => 'checkbox',
				/* translators: %s: module name. */
				'label'       => sprintf( __( 'Enable: %s', 'sentinel-shield' ), $meta[0] ),
				'help'        => $meta[1],
				'recommended' => true,
			);
			if ( $meta[2] ) {
				$fields[] = array(
					'key'         => "modules.$slug.test_mode",
					'tab'         => 'modules',
					'type'        => 'select',
					'options'     => $test_mode_options,
					/* translators: %s: module name. */
					'label'       => sprintf( __( 'Test mode: %s', 'sentinel-shield' ), $meta[0] ),
					'help'        => __( 'Override the global test mode for this module only.', 'sentinel-shield' ),
					'recommended' => 'inherit',
				);
			}
		}
		return $fields;
	}

	/**
	 * Looks up one field by key.
	 *
	 * @param string $key Dot path.
	 * @return array<string, mixed>|null
	 */
	public static function field( string $key ): ?array {
		foreach ( self::fields() as $field ) {
			if ( $field['key'] === $key ) {
				return $field;
			}
		}
		return null;
	}

	/**
	 * Sanitizes one value. Returns [value, error message or null].
	 *
	 * @param array<string, mixed> $field Field definition.
	 * @param mixed                $value Raw value.
	 * @return array{0:mixed, 1:?string}
	 */
	public static function sanitize_field( array $field, mixed $value ): array {
		$default = Settings::get_path( Settings::defaults(), (string) $field['key'] );
		switch ( $field['type'] ) {
			case 'checkbox':
				return array( is_bool( $value ) ? $value : filter_var( $value, FILTER_VALIDATE_BOOLEAN ), null );
			case 'select':
				$value = is_scalar( $value ) ? (string) $value : '';
				if ( isset( $field['options'][ $value ] ) ) {
					return array( $value, null );
				}
				/* translators: %s: setting label. */
				return array( $default, sprintf( __( '%s: invalid choice, default restored.', 'sentinel-shield' ), $field['label'] ) );
			case 'number':
				$int = is_numeric( $value ) ? (int) $value : (int) $default;
				return array( max( (int) $field['min'], min( (int) $field['max'], $int ) ), null );
			case 'header':
				$clean = preg_replace( '/[^A-Za-z0-9\-]/', '', is_scalar( $value ) ? (string) $value : '' );
				return array( '' === $clean ? $default : substr( (string) $clean, 0, 64 ), null );
			case 'textarea':
				return array( sanitize_textarea_field( is_scalar( $value ) ? (string) $value : '' ), null );
			case 'country_list':
				[ $codes, $invalid ] = CountryList::parse( is_scalar( $value ) ? (string) $value : '' );
				$error               = $invalid
					/* translators: 1: setting label, 2: list of entries. */
					? sprintf( __( '%1$s: ignored unknown country codes: %2$s', 'sentinel-shield' ), $field['label'], implode( ', ', array_map( 'sanitize_text_field', $invalid ) ) )
					: null;
				return array( implode( ', ', $codes ), $error );
			case 'url':
				$url = esc_url_raw( trim( is_scalar( $value ) ? (string) $value : '' ), array( 'https' ) );
				if ( '' === $url && '' !== trim( is_scalar( $value ) ? (string) $value : '' ) ) {
					/* translators: %s: setting label. */
					return array( '', sprintf( __( '%s: only https:// addresses are accepted.', 'sentinel-shield' ), $field['label'] ) );
				}
				return array( substr( $url, 0, 500 ), null );
			case 'hex_id':
				$clean = strtolower( (string) preg_replace( '/[^A-Fa-f0-9]/', '', is_scalar( $value ) ? (string) $value : '' ) );
				return array( substr( $clean, 0, 64 ), null );
			case 'server_var':
				$clean = strtoupper( (string) preg_replace( '/[^A-Za-z0-9_]/', '', is_scalar( $value ) ? (string) $value : '' ) );
				return array( substr( $clean, 0, 64 ), null );
			case 'cidr_list':
				$valid   = array();
				$invalid = array();
				$broad   = array();
				foreach ( IpRangeSet::parse_lines( is_scalar( $value ) ? (string) $value : '' ) as $line ) {
					$cidr = Cidr::parse( $line );
					if ( null === $cidr ) {
						$invalid[] = $line;
					} elseif ( isset( $field['min_prefix'][ $cidr->version ] ) && $cidr->prefix < (int) $field['min_prefix'][ $cidr->version ] ) {
						$broad[] = $cidr->to_string();
					} else {
						$valid[] = $cidr->to_string();
					}
				}
				$error = $invalid
					/* translators: 1: setting label, 2: list of invalid entries. */
					? sprintf( __( '%1$s: ignored invalid entries: %2$s', 'sentinel-shield' ), $field['label'], implode( ', ', array_map( 'sanitize_text_field', $invalid ) ) )
					: null;
				if ( $broad ) {
					/* translators: 1: setting label, 2: list of ranges. */
					$broad_error = sprintf( __( '%1$s: ignored ranges that are too broad to trust (anyone inside them could fake their IP): %2$s', 'sentinel-shield' ), $field['label'], implode( ', ', $broad ) );
					$error       = null === $error ? $broad_error : $error . ' ' . $broad_error;
				}
				return array( implode( "\n", array_unique( $valid ) ), $error );
			default:
				return array( sanitize_text_field( is_scalar( $value ) ? (string) $value : '' ), null );
		}
	}

	/**
	 * Sanitizes the fields of one tab and merges them into the current settings.
	 *
	 * @param string               $tab     Tab slug.
	 * @param array<string, mixed> $input   Raw nested input.
	 * @param array<string, mixed> $current Current settings.
	 * @return array{0:array<string, mixed>, 1:list<string>}
	 */
	public static function sanitize_tab( string $tab, array $input, array $current ): array {
		$errors = array();
		foreach ( self::fields() as $field ) {
			if ( $field['tab'] !== $tab ) {
				continue;
			}
			// Unchecked checkboxes are absent from POST data.
			$raw = Settings::get_path( $input, $field['key'], 'checkbox' === $field['type'] ? false : null );
			if ( null === $raw ) {
				continue;
			}
			[ $value, $error ] = self::sanitize_field( $field, $raw );
			Settings::set_path( $current, $field['key'], $value );
			if ( null !== $error ) {
				$errors[] = $error;
			}
		}
		return array( $current, $errors );
	}

	/**
	 * Sanitizes a full settings document (JSON import). Missing keys get defaults.
	 *
	 * @param array<string, mixed> $input Raw settings.
	 * @return array{0:array<string, mixed>, 1:list<string>}
	 */
	public static function sanitize_all( array $input ): array {
		$out    = Settings::defaults();
		$errors = array();
		foreach ( self::fields() as $field ) {
			if ( ! Settings::has_path( $input, $field['key'] ) ) {
				continue;
			}
			[ $value, $error ] = self::sanitize_field( $field, Settings::get_path( $input, $field['key'] ) );
			Settings::set_path( $out, $field['key'], $value );
			if ( null !== $error ) {
				$errors[] = $error;
			}
		}
		return array( Settings::apply_test_mode_expiry( $out ), $errors );
	}
}
