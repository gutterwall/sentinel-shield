<?php
/**
 * The Documentation tab on the settings page.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;

defined( 'ABSPATH' ) || exit;

/**
 * Explains administrator approvals in detail, then lists every setting from the
 * schema (so the reference can never fall out of step with the settings form),
 * the wp-config.php constants and the WP-CLI commands.
 */
final class DocsTab {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Renders the tab.
	 */
	public function render(): void {
		echo '<div class="ss-card ss-docs">';
		echo '<h2>' . esc_html__( 'Contents', 'sentinel-shield' ) . '</h2><ol>';
		$sections = array(
			'ss-doc-admins'    => __( 'Administrator approvals (who may be an administrator)', 'sentinel-shield' ),
			'ss-doc-login'     => __( 'Login security: brute-force protection and two-factor authentication', 'sentinel-shield' ),
			'ss-doc-scans'     => __( 'Malware scan, file integrity, health and performance', 'sentinel-shield' ),
			'ss-doc-edge'      => __( 'Early firewall, server and Cloudflare blocking', 'sentinel-shield' ),
			'ss-doc-audit'     => __( 'Alerts and the remote audit log', 'sentinel-shield' ),
			'ss-doc-privacy'   => __( 'What leaves this site, and what Sentinel Shield does not do', 'sentinel-shield' ),
			'ss-doc-settings'  => __( 'Every setting and what it does', 'sentinel-shield' ),
			'ss-doc-constants' => __( 'wp-config.php constants', 'sentinel-shield' ),
			'ss-doc-recovery'  => __( 'Locked out? Ways back in', 'sentinel-shield' ),
			'ss-doc-cli'       => __( 'WP-CLI commands', 'sentinel-shield' ),
		);
		foreach ( $sections as $anchor => $title ) {
			echo '<li><a href="#' . esc_attr( $anchor ) . '">' . esc_html( $title ) . '</a></li>';
		}
		echo '</ol>';
		/* translators: %s: version number. */
		echo '<p class="description">' . esc_html( sprintf( __( 'Sentinel Shield %s. The settings reference is also in docs/SETTINGS.md in the source repository.', 'sentinel-shield' ), SENTINEL_SHIELD_VERSION ) ) . '</p></div>';

		$this->admins();
		$this->login();
		$this->scans();
		$this->edge();
		$this->audit();
		$this->privacy();
		$this->settings();
		$this->constants();
		$this->recovery();
		$this->cli();
	}

	/**
	 * Administrator approvals.
	 */
	private function admins(): void {
		$settings = $this->c->get( Settings::class );
		$registry = $this->c->get( AdminRegistry::class );
		$lock     = (bool) $settings->get( 'lockdown.admin_lock', false );
		$list     = $registry->is_fixed() ? array() : $registry->approvals();

		echo '<div class="ss-card ss-docs" id="ss-doc-admins"><h2>' . esc_html__( 'Administrator approvals', 'sentinel-shield' ) . '</h2>';

		echo '<h3>' . esc_html__( 'Current state on this site', 'sentinel-shield' ) . '</h3><p>';
		if ( $registry->is_fixed() ) {
			$entries = array_column( $registry->fixed_report(), 'entry' );
			echo View::pill( __( 'Fixed in wp-config.php', 'sentinel-shield' ), 'ok' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			/* translators: %s: list of logins. */
			echo esc_html( sprintf( __( 'SENTINEL_SHIELD_ADMINS is defined, so the lock is always enforced and only these accounts are administrators: %s.', 'sentinel-shield' ), $entries ? implode( ', ', $entries ) : __( '(none: every administrator is locked)', 'sentinel-shield' ) ) );
		} elseif ( ! $lock ) {
			echo View::pill( __( 'Administrator lock off', 'sentinel-shield' ), 'info' ) . ' ' . esc_html__( 'Every administrator has full rights. The approved list below is kept and takes effect when the lock is turned on.', 'sentinel-shield' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		} elseif ( ! $list ) {
			echo View::pill( __( 'Lock on, not enforced', 'sentinel-shield' ), 'warn' ) . ' ' . esc_html__( 'The lock is on but no account is approved, so nobody is locked. Approve at least one administrator.', 'sentinel-shield' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		} else {
			echo View::pill( __( 'Administrator lock enforced', 'sentinel-shield' ), 'ok' ) . ' ' . esc_html__( 'Only the accounts below have administrator rights.', 'sentinel-shield' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</p>';
		if ( $list ) {
			echo '<table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Approved account', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Approved', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'By', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $list as $id => $entry ) {
				$by = (int) ( $entry['by'] ?? 0 );
				if ( $by > 0 ) {
					$by_user = get_userdata( $by );
					$by_text = $by_user instanceof \WP_User ? (string) $by_user->user_login : '#' . $by;
				} else {
					$by_text = __( 'WP-CLI or plugin activation', 'sentinel-shield' );
				}
				/* translators: 1: login, 2: user ID. */
				echo '<tr><td>' . esc_html( sprintf( __( '%1$s (ID %2$d)', 'sentinel-shield' ), (string) ( $entry['login'] ?? '' ), (int) $id ) ) . '</td>';
				echo '<td>' . esc_html( wp_date( 'Y-m-d H:i', (int) ( $entry['at'] ?? 0 ) ) ) . '</td><td>' . esc_html( $by_text ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '<p><a class="button" href="' . esc_url( Admin::url( 'sentinel-shield-lockdown' ) . '#ss-admins' ) . '">' . esc_html__( 'Manage administrators', 'sentinel-shield' ) . '</a> <a class="button" href="' . esc_url( Admin::url( 'sentinel-shield-settings', array( 'tab' => 'lockdown' ) ) ) . '">' . esc_html__( 'Lockdown settings', 'sentinel-shield' ) . '</a></p>';

		$this->section(
			__( 'What it is for', 'sentinel-shield' ),
			array(
				__( 'Malware such as SC creates its own administrator account by writing straight into the database, so no WordPress hook fires and no email is sent, and then hides the account from the Users screen. Stolen admin passwords and vulnerable plugins that let visitors promote themselves end the same way: an administrator you never created.', 'sentinel-shield' ),
				__( 'The administrator lock turns "who is an administrator" from whatever the database says into a list you control. An account that has administrator powers but is not on the list is treated as having no capabilities at all (it can still log in and see its profile), however it got its powers.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Where the list is configured', 'sentinel-shield' ),
			array(
				__( 'The list is managed on Sentinel Shield → Malware Lockdown → Administrators, or with WP-CLI (wp sentinel admins, approve-admin, revoke-admin). It is not a field on these settings tabs, because it is a list of accounts rather than a preference: you approve real accounts that exist, and approvals are bound to the account, not typed in.', 'sentinel-shield' ),
				__( 'The list is stored in its own option (sentinel_shield_admin_approvals; network-wide on multisite). It is not part of the settings export or import and not reachable through wp sentinel settings-set, so importing settings from another site never approves accounts on this one.', 'sentinel-shield' ),
				__( 'Approving or withdrawing requires full administrator rights (manage_options; manage_network_options on multisite). A locked account has no rights, so it cannot approve itself.', 'sentinel-shield' ),
				__( 'Alternatively, the list can be fixed in wp-config.php with SENTINEL_SHIELD_ADMINS (next section). It then replaces the list in the database entirely.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Fixing the list in wp-config.php (SENTINEL_SHIELD_ADMINS)', 'sentinel-shield' ),
			array(
				__( 'Malware that can write to the database could add its own account to an approved list stored there. A list in wp-config.php can only be changed by someone who can edit the site\'s files. Add a line like this above "That\'s all, stop editing!":', 'sentinel-shield' ),
			)
		);
		echo '<pre class="ss-code"><code>define( \'SENTINEL_SHIELD_ADMINS\', \'admin#1, jane#7\' );</code></pre>';
		echo '<ul class="ul-disc">';
		foreach (
			array(
				__( 'Entries are logins separated by commas (an array of logins also works). Logins are matched without regard to case.', 'sentinel-shield' ),
				__( 'Adding #ID pins an entry to one account: "jane#7" approves login jane only while it belongs to user ID 7. Always pin. Without it, if the jane account is deleted, anyone who registers a new account called jane becomes an approved administrator. The Administrators list shows the ID to use for each entry.', 'sentinel-shield' ),
				__( 'While the constant is defined, the lock is always enforced: it does not depend on the "Administrator lock" checkbox, the Malware lockdown module or the "Enable protection" switch, all of which live in the database. Only SENTINEL_SHIELD_DISABLE switches it off.', 'sentinel-shield' ),
				__( 'The approved list in the database is ignored and kept unchanged; remove the constant to go back to it. Approve and Withdraw buttons and wp sentinel approve-admin / revoke-admin are disabled.', 'sentinel-shield' ),
				__( 'The list is applied exactly as written. If no entry matches an administrator (a typo, or an empty value), every administrator is locked until wp-config.php is corrected. Check the Administrators list right after saving the file.', 'sentinel-shield' ),
				__( 'Entries that match no account, or whose login now belongs to a different user ID, are shown on the Administrators list, reported by the malware scan and announced in an admin notice.', 'sentinel-shield' ),
				__( 'To add an administrator: create or promote the account, then add its login#ID to the constant. To remove one: delete its entry (and ideally its administrator role).', 'sentinel-shield' ),
			) as $text
		) {
			echo '<li>' . esc_html( $text ) . '</li>';
		}
		echo '</ul>';

		$this->section(
			__( 'Which accounts count as administrators', 'sentinel-shield' ),
			array(
				__( 'On a single site: any account with the Administrator role, or any account given one of these powers directly, whatever its role: manage_options, activate_plugins, install_plugins, edit_plugins, edit_files, update_core. Giving a "Subscriber" these capabilities is a known trick to hide an administrator; such accounts are marked "Admin powers without admin role".', 'sentinel-shield' ),
				__( 'On multisite: super administrators. Site administrators of individual sites are not affected by the lock.', 'sentinel-shield' ),
				__( 'Accounts are found with a direct database query, not with WordPress\'s user search, which malware can filter. Each account is then compared with what the Users screen would show; accounts missing from the Users screen are marked "Hidden from Users screen", the clearest sign of a backdoor account.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Turning the lock on', 'sentinel-shield' ),
			array(
				__( 'Tick "Administrator lock" on the Malware Lockdown settings tab and save. If nobody is approved yet, every administrator that the Users screen shows is approved automatically, plus you. Hidden accounts are never approved automatically, so a hidden backdoor admin is locked the moment you save.', 'sentinel-shield' ),
				__( 'Before you turn it on, open the Administrators list and check for accounts you do not recognize. Delete them first if you can.', 'sentinel-shield' ),
				__( 'While the list is empty the lock does nothing. This is deliberate: switching the lock on (or withdrawing every approval with WP-CLI) can never lock out every administrator.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Adding a new administrator later', 'sentinel-shield' ),
			array(
				__( 'Create or promote the account as usual. With the lock enforced, the new account has no rights yet. Approved administrators see a notice listing accounts waiting for approval, and the site admin email receives a "New administrator account" message (if "Alert on new administrator accounts" is on) saying who made the change and from which IP.', 'sentinel-shield' ),
				__( 'Approve it on Malware Lockdown → Administrators (you are asked to confirm, with an extra warning for hidden accounts) or run wp sentinel approve-admin <user>. The account has full rights on its next page load.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'What a locked account experiences', 'sentinel-shield' ),
			array(
				__( 'It can log in and reach its profile, but every admin screen and every action needing a capability is refused with "Sorry, you are not allowed to access this page". A red notice explains that its administrator rights are suspended and how an approved administrator can approve it.', 'sentinel-shield' ),
				__( 'The lock works at WordPress\'s permission check (map_meta_cap), so it also applies to the REST API, AJAX, XML-RPC and code acting as that user, and to super administrators on multisite.', 'sentinel-shield' ),
				__( 'Each locked account using the admin is logged once an hour as "Unapproved administrator denied" in the Events log.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Withdrawing approval and other changes', 'sentinel-shield' ),
			array(
				__( 'Withdraw approval with the button on the Administrators list or wp sentinel revoke-admin <user>. You cannot withdraw your own approval from the admin, so you cannot lock yourself out by accident.', 'sentinel-shield' ),
				__( 'An approval is bound to both the user ID and the login name. If an account\'s login is changed (only possible through the database or code), the approval no longer matches and the account must be approved again.', 'sentinel-shield' ),
				__( 'Removing someone\'s administrator role does not remove their approval; it simply stops mattering. If they are made administrator again, the old approval applies. Withdraw approval when someone leaves.', 'sentinel-shield' ),
				__( 'Approvals and withdrawals are written to the Events log with the acting user.', 'sentinel-shield' ),
			)
		);

		$this->section(
			__( 'Limits', 'sentinel-shield' ),
			array(
				__( 'Without SENTINEL_SHIELD_ADMINS the approved list lives in the database, where malware that specifically targets Sentinel Shield could add its own account. Use the wp-config.php list to close that gap. Either way, keep the twice-daily scan and the email alerts on: they report hidden administrators, database triggers and new administrators independently.', 'sentinel-shield' ),
				__( 'The wp-config.php list cannot be changed through the database, but it is only enforced while Sentinel Shield is running. Malware that writes to the database directly could still remove Sentinel Shield from the list of active plugins; the plugin then stops loading altogether, which you would notice on the Plugins screen. Malware that can edit files can also edit wp-config.php. The list is not a defence against full server compromise.', 'sentinel-shield' ),
				__( 'The lock limits what an account can do inside WordPress. It does not stop code that is already running on the server; that is what the scan and the other lockdown measures are for.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * What leaves the site, and the plugin's scope.
	 */
	private function privacy(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-privacy"><h2>' . esc_html__( 'What leaves this site, and what Sentinel Shield does not do', 'sentinel-shield' ) . '</h2>';
		$this->section(
			__( 'Connections to other services', 'sentinel-shield' ),
			array(
				__( 'Sentinel Shield sends nothing about your visitors to any service unless you set up the remote audit log or Cloudflare sync. Everything else is a download your server makes; the provider sees your server\'s IP address and when it checks.', 'sentinel-shield' ),
				__( 'On by default: the file integrity check asks WordPress.org (api.wordpress.org, downloads.wordpress.org) for the published checksums of your WordPress version and locale and of each installed plugin and version, the same information WordPress\'s own update checks send. Switch it off on the Malware Lockdown tab.', 'sentinel-shield' ),
				__( 'Only when you choose them: each blocklist you enable is downloaded from its provider with a generic "SentinelShield" user agent and no site address; the DB-IP country database comes from db-ip.com; Cloudflare\'s address ranges come from api.cloudflare.com when the Cloudflare IP preset is selected.', 'sentinel-shield' ),
				__( 'Cloudflare sync sends the blocked addresses and ranges of the current policy (no visitor data beyond those addresses) to your own Cloudflare account, with your API token.', 'sentinel-shield' ),
				__( 'The remote audit log sends each event to your webhook as JSON with these fields: id, time, event, module, ip, reason, uri (the requested path and query string, with reset keys, nonces, passwords and tokens masked), agent (the browser\'s user agent), user_id, test, context (event details, such as the username that was tried, a country code or a file path), plus seq, prev and hash for the chain; each delivery also carries the site address. Syslog lines hold only site (host name), id, event, module, ip and reason; where your system log goes from there is up to your server.', 'sentinel-shield' ),
				__( 'The heartbeat is a plain request to the URL you enter, with no data. Emails (alerts to the site admin address, two-factor codes and unlock links to the account\'s address) go through WordPress\'s mailer and whatever mail service it uses. To confirm the private folder cannot be downloaded, the site may request a test file from itself.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'What it does not do', 'sentinel-shield' ),
			array(
				__( 'Sentinel Shield blocks by IP address, account and country, hardens logins, and detects tampering. It has no vulnerability database: it does not tell you which installed plugins or themes have known security holes, and it has no virtual patches for them. It does not inspect request contents for attacks such as SQL injection or cross-site scripting, so an exploit sent from an address that is not on a blocklist reaches WordPress. It cannot absorb a volumetric DDoS attack, which has to be stopped upstream (your host or a CDN). It does not make backups or remove malware for you. Use it alongside updates, backups kept off the server and, where needed, those services.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * Settings reference generated from the schema.
	 */
	private function settings(): void {
		$defaults = Settings::defaults();
		$fields   = SettingsSchema::fields();
		echo '<div class="ss-card ss-docs" id="ss-doc-settings"><h2>' . esc_html__( 'Every setting and what it does', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Defaults are what a fresh install uses. Recommended values are shown as a badge next to each setting on its tab. The key is the name used by wp sentinel settings-get / settings-set and in exported settings files.', 'sentinel-shield' ) . '</p>';
		foreach ( SettingsSchema::tabs() as $tab => $title ) {
			$mine = array_filter( $fields, static fn( array $f ): bool => $f['tab'] === $tab );
			if ( ! $mine ) {
				continue;
			}
			echo '<h3><a href="' . esc_url( Admin::url( 'sentinel-shield-settings', array( 'tab' => $tab ) ) ) . '">' . esc_html( $title ) . '</a></h3>';
			echo '<div class="ss-scroll"><table class="widefat striped"><thead><tr><th style="width:24%">' . esc_html__( 'Setting', 'sentinel-shield' ) . '</th><th style="width:10%">' . esc_html__( 'Default', 'sentinel-shield' ) . '</th><th style="width:12%">' . esc_html__( 'Recommended', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'What it does', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $mine as $field ) {
				$rec = View::recommended_text( $field );
				echo '<tr><td><strong>' . esc_html( (string) $field['label'] ) . '</strong><br><code>' . esc_html( (string) $field['key'] ) . '</code>';
				if ( in_array( $field['key'], Settings::OVERRIDABLE, true ) ) {
					echo '<br>' . View::pill( __( 'Per-site on multisite', 'sentinel-shield' ), 'info' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
				}
				echo '</td><td>' . esc_html( self::value_text( $field, Settings::get_path( $defaults, (string) $field['key'] ) ) ) . '</td>';
				echo '<td>' . esc_html( '' === $rec ? __( 'Your choice', 'sentinel-shield' ) : $rec ) . '</td>';
				echo '<td>' . esc_html( (string) ( $field['help'] ?? '' ) ) . '</td></tr>';
			}
			echo '</tbody></table></div>';
		}
		echo '</div>';
	}

	/**
	 * Constants read from wp-config.php.
	 */
	private function constants(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-constants"><h2>' . esc_html__( 'wp-config.php constants', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Add these above the line "That\'s all, stop editing!".', 'sentinel-shield' ) . '</p><table class="widefat striped ss-narrow"><tbody>';
		$rows = array(
			"define( 'SENTINEL_SHIELD_DISABLE', true );" => __( 'Emergency switch: Sentinel Shield loads nothing (no blocking, no lockdown measures). Use it to get back in, fix the cause, then remove the line.', 'sentinel-shield' ),
			"define( 'SENTINEL_SHIELD_ADMINS', 'admin#1, jane#7' );" => __( 'Fixes the approved administrator list in this file and always enforces the administrator lock. Pin each login to its user ID with #ID. See "Administrator approvals" above.', 'sentinel-shield' ),
			"define( 'SENTINEL_SHIELD_DATA_DIR', '/srv/private/sentinel-shield' );" => __( 'The private folder for the early firewall snapshot, its block log and the server blocklist files. It must be outside the web root and writable by PHP. Default: a sentinel-shield-data folder next to the WordPress folder.', 'sentinel-shield' ),
			"define( 'DISALLOW_FILE_EDIT', true );"      => __( 'WordPress\'s own switch for the plugin and theme file editor. Stronger than the lockdown setting because it lives in a file instead of the database.', 'sentinel-shield' ),
			"define( 'DISABLE_WP_CRON', true );"         => __( 'Stops page loads from running scheduled tasks. Only use it with a real server cron job (the line is shown on the Scheduled Tasks page), otherwise blocklist updates and the malware scan stop.', 'sentinel-shield' ),
		);
		foreach ( $rows as $code => $text ) {
			echo '<tr><td><code>' . esc_html( $code ) . '</code></td><td>' . esc_html( $text ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * Brute-force protection and two-factor authentication.
	 */
	private function login(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-login"><h2>' . esc_html__( 'Login security', 'sentinel-shield' ) . '</h2>';
		$this->section(
			__( 'Brute-force protection', 'sentinel-shield' ),
			array(
				__( 'Every failed login is counted: a wrong password, a username that does not exist, and a wrong two-factor code. Failures are counted per IP and per account over the counting window (15 minutes by default). Allowlisted IPs and this server are never counted.', 'sentinel-shield' ),
				__( 'Per IP: when one IP reaches the limit (5 by default) it is locked out with the progressive lockouts from the Lockouts & Unlock tab: 15 minutes, then 1 hour, 24 hours and finally a permanent block if it keeps coming back within the repeat window. The lockout appears on the IP Rules page and blocks the whole site for that IP. The login in progress is refused as well, so an XML-RPC "multicall" request cannot try hundreds of passwords at once.', 'sentinel-shield' ),
				__( 'Per account: attackers often spread guesses over thousands of IPs, a few each. When one account reaches its limit (20 by default) from any number of IPs, password logins to it are refused for a while, except from IPs that account logged in from successfully before (its last 10, for 90 days) and allowlisted IPs. No IP is locked out for this, so an attacker cannot use it to block the real user, who usually logs in from a known IP.', 'sentinel-shield' ),
				__( 'A refused login always gets "Too many failed login attempts", whether or not the password was right, so the limits cannot be used to test passwords. With "Do not reveal which usernames exist", wrong usernames and wrong passwords get the same message too.', 'sentinel-shield' ),
				__( 'Limits are checked before WordPress checks the password, so a refused login costs no password hashing. Logins from one IP are handled one at a time from that check until the result is counted; a login that would have to wait more than a second is refused (not counted), so simultaneous requests cannot slip past the limit. When an IP is locked out, only its own count restarts: its failures keep counting against the accounts it tried, so an attacker cannot erase them by moving on to new IPs. The same limits apply to application passwords sent to the REST API, and every wrong one counts.', 'sentinel-shield' ),
				__( 'Usernames on the instant lockout list (such as admin, when no account uses it) lock an IP out at its first try. Turning off XML-RPC logins closes the most common brute-force target if nothing on the site needs it.', 'sentinel-shield' ),
				__( 'Test mode: logins over a limit are allowed and logged as "would deny login", and lockouts are logged as "would lock out". The Login Security tab lists the IPs and accounts with the most failed logins in the last 24 hours.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Two-factor authentication', 'sentinel-shield' ),
			array(
				__( 'After a correct password, accounts with two-factor authentication are asked for a code before they are logged in. No login cookie exists until the code is right. The code screen lasts 10 minutes and allows five tries; each wrong code counts as a failed login for the brute-force limits.', 'sentinel-shield' ),
				__( 'Limits are per account, not per login, so starting the login again resets nothing: at most 10 code screens, 6 emailed codes (one a minute) and 15 wrong codes an hour per account. Up to three code screens can be open at once, so someone else starting a login does not cancel yours, and a correct code closes them all.', 'sentinel-shield' ),
				__( 'Passkeys and security keys are the strongest method: a phone, the computer\'s Windows Hello or Touch ID, or a security key such as a YubiKey confirms the login with a fingerprint, face or PIN. A passkey only works on this site, so it cannot be phished. Each user can add several (name them so they can tell them apart). Passkeys need an https:// site (or localhost).', 'sentinel-shield' ),
				__( 'Fresh confirmation: adding or removing any method (passkey, app, email codes) or creating new backup codes needs the user to confirm their identity within the last 10 minutes in the same login session: with a passkey, or with their password plus a code from their authenticator app or a backup code once they have one. Five wrong confirmations in 15 minutes block further tries for a while, and each one counts as a failed login for the brute-force limits. Someone who steals a login cookie therefore cannot plant their own authenticator, or guess the password from inside the session. Administrators resetting another user\'s two-factor confirm their own password.', 'sentinel-shield' ),
				__( 'Methods, set up by each user under Users → Two-Factor Authentication: an authenticator app (any app that supports time-based codes; the QR code is drawn by this site, so the secret never leaves it), codes by email (8 digits, valid 10 minutes, if this site allows them), and ten one-time backup codes for a lost phone. Authenticator secrets are encrypted with keys from wp-config.php; backup and email codes are stored only as keyed hashes.', 'sentinel-shield' ),
				__( 'Requiring it: "Required for administrator-level accounts" (recommended) or "for every account". An account that is required to use it but has no authenticator app gets a code by email at each login and a reminder in the dashboard until it sets one up. If email codes are off, such accounts cannot log in at all until an app is set up for them; the Login Security tab lists them, and you cannot switch email codes off while your own login needs them. A required account is never let in with only its password. Check that this site can send email before requiring it.', 'sentinel-shield' ),
				__( 'XML-RPC and the REST API cannot show a code screen, so password logins there are refused for two-factor accounts. Application passwords (Users → Profile) keep working: they are separate, revocable secrets that only a logged-in user can create.', 'sentinel-shield' ),
				__( 'If an administrator changes the security keys and salts in wp-config.php, stored authenticator secrets can no longer be read. Those users log in with a backup or email code and set up their app again; an account with no other method needs a reset.', 'sentinel-shield' ),
				__( 'Lost phone: use a backup code, or an email code if allowed. Otherwise another administrator ticks "Reset two-factor authentication" on the user\'s profile, or run wp sentinel 2fa <user> --reset.', 'sentinel-shield' ),
				__( '"Trust this browser" (if offered) skips the code on that browser for the chosen number of days. Each user sees their trusted browsers (browser, IP, when added and last used) on their Two-Factor Authentication page and can revoke any one or all. Changing or resetting the password, and adding, replacing or removing an authenticator app or email codes, revokes them all, together with any open code screens.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * The malware scan and the checksum verification.
	 */
	private function scans(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-scans"><h2>' . esc_html__( 'Malware scan and file integrity check', 'sentinel-shield' ) . '</h2>';
		$this->section(
			__( 'Malware scan', 'sentinel-shield' ),
			array(
				__( 'Twice a day the scan looks at every place the SC malware and similar takeovers hide: PHP auto-prepend settings, drop-ins, must-use and hidden plugins, administrator accounts, database triggers, the theme, hidden PHP files and restore bundles, encoded database options, scheduled tasks, login hooks, shared memory and blockchain command channels. It only reads; nothing is changed.', 'sentinel-shield' ),
				__( 'Coverage is reported with every scan: how many files were read, files over 2 MB of which only the first 2 MB was checked, files and folders that could not be read, and folder links that were not followed. A check that stops listing after 100 findings says so.', 'sentinel-shield' ),
				__( 'The uploads folder can hold hundreds of thousands of files. Each run checks up to 20,000 of them (or 20 seconds\' worth) and remembers where it stopped; the next run, a couple of minutes later, continues from there until every file has been checked. Findings from the part already checked stay in the report meanwhile. WP-CLI (wp sentinel scan) checks everything in one go.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'File integrity (WordPress.org checksums)', 'sentinel-shield' ),
			array(
				__( 'WordPress.org publishes a hash of every file of every WordPress release and of every version of every plugin it hosts. Once a day, each core file and each file of plugins from WordPress.org is compared with those hashes. Any change shows up, not just known malware tricks: a changed core file is critical, a PHP file in wp-admin or wp-includes that no release contains is critical, an unknown PHP file in the WordPress folder is a warning, and a changed or added PHP file in a plugin is a warning (critical when it also looks like malware). Missing files are listed for review.', 'sentinel-shield' ),
				__( 'Not everything can be verified: WordPress.org publishes no checksums for themes, premium and custom plugins are not hosted there, and single-file plugins have no folder to check. These are listed as "not verifiable" with the reason, and the malware scan still covers them.', 'sentinel-shield' ),
				__( 'The check runs in slices of about 15 seconds, a minute apart, and keeps its place in between, so large sites are checked completely. Published checksums are cached for 30 days (they never change for a given version). Your site asks WordPress.org for the checksums of your WordPress and plugin versions, as its update checks already do; nothing about visitors is sent.', 'sentinel-shield' ),
				__( 'If you edit plugin files on purpose, approve the finding: you are warned again only if the file changes. To fix a changed core file, reinstall WordPress (Dashboard → Updates); reinstalling does not remove extra files, which have to be deleted by hand once you know what they are.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Enforcement health and performance', 'sentinel-shield' ),
			array(
				__( 'The dashboard\'s Enforcement health card (and wp sentinel health) checks that protection really works: switched on and out of test mode (new installations start in test mode with no end date), IP detection sound, concurrency locks working, scans and maintenance running on time, blocklists and the country database fresh, and no open scan findings.', 'sentinel-shield' ),
				__( 'Logins, code checks and unlock requests use database named locks (GET_LOCK) so parallel requests cannot get around the limits. Database proxies and clusters that do not pass named locks through, and non-MySQL databases, get a lock row in the options table instead (slower, shown as degraded). If no lock can be taken at all, those operations are refused rather than run unprotected, and the health card shows it.', 'sentinel-shield' ),
				__( 'Blocked requests cost little: rule matches and hit counts are cached with a persistent object cache such as Redis (hit counts are written at most once a minute per rule); without one, hit counts are approximate (at most one per IP per minute). Blocklists are compiled into a compact file in uploads/sentinel-shield after each update and looked up with a few small reads, whatever their size. Old rows are deleted in small batches, and report figures on admin screens may be up to a minute old.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Automatic administrator allowlist entries', 'sentinel-shield' ),
			array(
				__( 'When an administrator activates the plugin or saves settings, their IP is allowlisted so they cannot lock themselves out. These entries last 30 days by default and renew whenever an administrator uses the dashboard from that IP, so only addresses nobody has used for a month drop off. Home and mobile IPs change and are reassigned to other people; a permanent entry could end up trusting a stranger. Set the number of days on the Lockouts & Unlock tab (0 keeps them forever). Entries you add yourself are never changed.', 'sentinel-shield' ),
				__( 'Automatic entries only keep the IP from being blocked. They do not exempt it from the login limits or the login location rules, because everyone behind the same office, VPN or public Wi-Fi address would be exempt too. To exempt an address from those as well, add it to the allowlist yourself on the IP Rules page.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * Early firewall, server files and Cloudflare.
	 */
	private function edge(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-edge"><h2>' . esc_html__( 'Early firewall, server and Cloudflare blocking', 'sentinel-shield' ) . '</h2>';
		$this->section(
			__( 'One policy for every layer', 'sentinel-shield' ),
			array(
				__( 'WordPress, the early firewall, the server blocklist files and the Cloudflare list all apply the same policy: the enforced block rules minus the allowlist and this server\'s own addresses. An allowlisted address is therefore never blocked by any layer, even when it falls inside a blocked range (the range is split around it). While protection, the IP gate module or SENTINEL_SHIELD_DISABLE switches enforcement off, the policy is empty everywhere. Each change gets a new generation number, shown on the Server & CDN tab, so you can see whether every layer has caught up.', 'sentinel-shield' ),
				__( 'The policy is rebuilt once at the end of any request that changed rules, and again the moment the next temporary rule expires, so short lockouts end everywhere on time (Cloudflare within its update interval, the web server at its next reload).', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'The private folder', 'sentinel-shield' ),
			array(
				__( 'The snapshot (which contains your allowlisted addresses), the early firewall\'s block log and the server blocklist files are written to a private folder outside the web root: sentinel-shield-data next to the WordPress folder, or the folder set with SENTINEL_SHIELD_DATA_DIR. Rules in .htaccess only work on Apache, so they are not relied on. The folder counts as private only when it is outside the web server\'s document root, or when a test file placed in it cannot be downloaded. Until that is confirmed, none of these files are written, and the Server & CDN tab and the health card say why.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Early firewall', 'sentinel-shield' ),
			array(
				__( 'The normal firewall runs when Sentinel Shield loads, after WordPress itself and any plugins loaded before it. The early firewall (early-gate.php) runs first: as a must-use plugin before other plugins, or through auto_prepend_file before WordPress and before any other PHP file on the site. A blocked IP then costs almost nothing, even during a flood.', 'sentinel-shield' ),
				__( 'It does not load WordPress. It reads the snapshot (gate.json and two compact binary range files) from the private folder: your proxy setup, the allowlist, the effective block policy and the compiled blocklist feeds, all looked up with a binary search. The snapshot expires with the next rule expiry (at most a day); a stale, missing or damaged snapshot makes the early firewall step aside, so it never blocks more than WordPress would. Requests through a proxy it cannot verify, this server\'s cron requests and unlock links are left to WordPress. Its blocks appear in the event log (module early_gate) within the hour; during a flood, only one block in ten is logged once the log passes 100 KB.', 'sentinel-shield' ),
				__( 'For auto_prepend_file, add the line shown on the Server & CDN tab to php.ini, .user.ini, an Apache php_value line or nginx\'s PHP_VALUE, then restart PHP. Only one file can be prepended; if another security plugin uses it (Wordfence does), use the must-use plugin option. The malware scan recognizes this plugin\'s own gate and loader and does not report them, unless they were changed.', 'sentinel-shield' ),
				__( 'Emergency switch-off without WordPress: create an empty file named gate.disabled next to gate.json (or delete gate.json).', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Blocking at the web server or at Cloudflare', 'sentinel-shield' ),
			array(
				__( 'PHP only runs for PHP requests; images, scripts and other static files are served without it. To refuse blocked IPs for everything, let the web server or the CDN do it. "Write nginx and Apache blocklist files" keeps nginx-deny.conf and apache-deny.conf in the private folder current with the policy (manual rules and lockouts; blocklist feeds are left out because they can be very large): include the file in the server configuration. The web server only applies changes after a reload, so reload regularly or leave short lockouts to WordPress and the early firewall.', 'sentinel-shield' ),
				__( 'With Cloudflare, Sentinel Shield replaces the items of one Cloudflare account IP list with the policy (at most 10,000 entries) and then asks Cloudflare until its bulk operation has completed; the list only shows as active after that. Uploads happen at most every five minutes and only when the list changed; an emptied policy is sent at once. Cloudflare lists take IPv6 ranges up to /64 only: single IPv6 addresses are left out by default (WordPress still blocks them), or widened to their /64 with the IPv6 setting, never over an allowlisted address. Create an IP list, an API token with "Account Filter Lists: Edit", and a WAF custom rule (ip.src in $your_list) with the action Block. The token is stored encrypted and never exported.', 'sentinel-shield' ),
				__( 'Switching off: when protection is off, the server files and the Cloudflare list get the empty policy. Turning Cloudflare sync off, or deactivating the plugin, empties the Cloudflare list (if that fails, the Server & CDN tab says the rules are still active at Cloudflare). Deactivating also removes the must-use loader and the snapshot and empties the server files, which are kept so the server configuration that includes them keeps working. Uninstalling deletes the private folder\'s files.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * Alerts, delivery checks and the remote audit log.
	 */
	private function audit(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-audit"><h2>' . esc_html__( 'Alerts and the remote audit log', 'sentinel-shield' ) . '</h2>';
		$this->section(
			__( 'Alert delivery', 'sentinel-shield' ),
			array(
				__( 'Every email Sentinel Shield sends (security alerts, two-factor codes, unlock links) records whether it was accepted by the mail system (WordPress\'s mailer and the mail server it hands off to), with the error message when not. Whether it then reaches the inbox cannot be checked from the site. A failing alert email shows as a problem on the Enforcement health card, and Settings → Alerts & Audit Log lists the last success and failure per kind. "Send a test alert" tries every channel at once.', 'sentinel-shield' ),
				__( 'A heartbeat URL is pinged every hour; a monitoring service such as healthchecks.io alerts you when the pings stop, which is what happens when the site is down, Sentinel Shield was switched off, or scheduled jobs stopped.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Remote audit log', 'sentinel-shield' ),
			array(
				__( 'Whoever takes over a site can empty its database, and with it the event log. With a webhook set, security events (or all events) are POSTed as JSON to your endpoint by a background job that starts within seconds of the event (never inside a visitor\'s request), with growing delays between retries while the endpoint is down, so nothing is lost. Events can also go to the server\'s syslog (facility auth, tag sentinel-shield), written immediately.', 'sentinel-shield' ),
				__( 'Each delivery is signed: the header X-Sentinel-Shield-Signature carries t=<time>,v1=HMAC-SHA256(secret, "<time>.<body>"). Each event carries seq (a running number), prev and hash, where hash is SHA-256 of prev, a newline and the event\'s JSON without seq, prev and hash. A gap in seq, or a prev that is not the previous hash, means events are missing or were changed. wp sentinel audit-export prints the stored events in the same format, for SIEM imports or an offline copy.', 'sentinel-shield' ),
			)
		);
		echo '</div>';
	}

	/**
	 * Recovery options.
	 */
	private function recovery(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-recovery"><h2>' . esc_html__( 'Locked out? Ways back in', 'sentinel-shield' ) . '</h2><table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Problem', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Fix', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		$rows = array(
			array( __( 'Your IP is blocked', 'sentinel-shield' ), __( 'wp sentinel unblock <ip> --allow-hours=24, or "Send unlock link" on the block page (403 mode, Emailed unlock links module on), or the SENTINEL_SHIELD_DISABLE constant. Unlock emails are limited: one per account every 5 minutes, 3 per account and 10 per site per hour, at most 2 unused links per account, plus the per-IP setting. Over a limit, the form gives the usual answer but sends nothing. A link stops working if its account is deleted or can no longer manage the site.', 'sentinel-shield' ) ),
			array( __( 'Your administrator rights are suspended', 'sentinel-shield' ), __( 'Ask an approved administrator to approve you, or run wp sentinel approve-admin <your login>. If SENTINEL_SHIELD_ADMINS is defined, add your login#ID to it in wp-config.php instead. As a last resort, use the SENTINEL_SHIELD_DISABLE constant and approve yourself from the Malware Lockdown page, then remove the constant.', 'sentinel-shield' ) ),
			array( __( 'Your login is refused because of your location', 'sentinel-shield' ), __( 'Add your IP to the allowlist with wp sentinel allow <ip>, or change the countries with wp sentinel settings-set geo.countries "US, CA" (or geo.mode off). The SENTINEL_SHIELD_DISABLE constant also works. Check where an IP is with wp sentinel geo <ip>.', 'sentinel-shield' ) ),
			array( __( 'Too many failed logins', 'sentinel-shield' ), __( 'Wait for the lockout to end, or run wp sentinel unblock <ip> and wp sentinel login-attempts --clear --ip=<ip>. If your account is protected after an attack, log in from an IP you used before, or clear it with wp sentinel login-attempts --clear --account=<login>.', 'sentinel-shield' ) ),
			array( __( 'The early firewall blocks something it should not', 'sentinel-shield' ), __( 'Create an empty file named gate.disabled in uploads/sentinel-shield (or delete gate.json there): the early firewall then lets everything through. Remove the auto_prepend_file line or set Early firewall to Off to switch it off for good. It only ever blocks what the normal firewall would; check the rule with wp sentinel check <ip>.', 'sentinel-shield' ) ),
			array( __( 'You lost your two-factor phone', 'sentinel-shield' ), __( 'Use a backup code or an emailed code. Otherwise ask another administrator to reset two-factor on your profile, or run wp sentinel 2fa <your login> --reset. The SENTINEL_SHIELD_DISABLE constant also turns two-factor off.', 'sentinel-shield' ) ),
			array( __( 'You need to install a plugin or theme', 'sentinel-shield' ), __( 'Untick "Block installing and uploading plugins and themes" on the Malware Lockdown tab, install, then tick it again. Or install with WP-CLI.', 'sentinel-shield' ) ),
			array( __( 'A plugin needs a blockchain gateway', 'sentinel-shield' ), __( 'Untick "Block blockchain command channels", or allow the specific host with the sentinel_shield_allowed_chain_hosts filter.', 'sentinel-shield' ) ),
			array( __( 'You cannot deactivate Sentinel Shield', 'sentinel-shield' ), __( 'Deactivate it from the Plugins screen as an administrator, or run wp plugin deactivate sentinel-shield. Only code-initiated deactivation is refused.', 'sentinel-shield' ) ),
		);
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( $row[0] ) . '</td><td>' . esc_html( $row[1] ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * WP-CLI command list.
	 */
	private function cli(): void {
		echo '<div class="ss-card ss-docs" id="ss-doc-cli"><h2>' . esc_html__( 'WP-CLI commands', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'WP-CLI is never blocked. Run wp help sentinel <command> for every option.', 'sentinel-shield' ) . '</p><table class="widefat striped ss-narrow"><tbody>';
		$rows = array(
			'status'                            => __( 'Protection, test mode, IP detection and rule counts.', 'sentinel-shield' ),
			'check <ip>'                        => __( 'What would happen to a request from this IP, and why.', 'sentinel-shield' ),
			'resolve-ip'                        => __( 'Simulates client IP detection for given REMOTE_ADDR, headers and proxy preset.', 'sentinel-shield' ),
			'block <ip|cidr> / allow <ip|cidr>' => __( 'Adds a block or allow rule, optionally with a reason and expiry.', 'sentinel-shield' ),
			'unblock <ip> / remove <id>'        => __( 'Lifts blocks matching an IP (optionally allowlisting it), or deletes a rule by ID.', 'sentinel-shield' ),
			'list'                              => __( 'Lists IP rules.', 'sentinel-shield' ),
			'lockout <ip>'                      => __( 'Records an offense and applies the next lockout step (for testing).', 'sentinel-shield' ),
			'test-mode <on|off|status>'         => __( 'Turns global test mode on (optionally for N hours) or off, or shows it.', 'sentinel-shield' ),
			'settings-get / settings-set'       => __( 'Reads or changes one setting by key (see the reference above).', 'sentinel-shield' ),
			'settings-keys'                     => __( 'Lists every setting key.', 'sentinel-shield' ),
			'settings-export / settings-import' => __( 'Saves or loads all settings as JSON (administrator approvals are not included).', 'sentinel-shield' ),
			'cloudflare-update'                 => __( 'Downloads the current Cloudflare IP ranges.', 'sentinel-shield' ),
			'login-attempts'                    => __( 'Failed logins by IP and account; --ip / --account show whether a login is allowed now; --clear forgets them.', 'sentinel-shield' ),
			'2fa [<user>]'                      => __( 'Two-factor status of administrators and every account using it; --reset removes all methods of a user (lost phone).', 'sentinel-shield' ),
			'geo <ip>'                          => __( 'Shows an IP\'s country and whether a login from it would be allowed (--account=<user> for a specific account).', 'sentinel-shield' ),
			'geo-update'                        => __( 'Downloads the DB-IP country database now.', 'sentinel-shield' ),
			'feeds / feeds-update'              => __( 'Shows blocklist status, or downloads enabled lists now.', 'sentinel-shield' ),
			'cron'                              => __( 'Lists scheduled tasks with last-run status and origin.', 'sentinel-shield' ),
			'early-gate [rebuild]'              => __( 'Early firewall status and setup lines, or rebuild its snapshot and the server blocklist files now.', 'sentinel-shield' ),
			'server-export <format>'            => __( 'Prints the enforced blocklist for nginx, Apache, as plain text or in Cloudflare\'s format.', 'sentinel-shield' ),
			'cloudflare-sync [--test]'          => __( 'Syncs the blocklist to the Cloudflare IP list now, or only checks the connection.', 'sentinel-shield' ),
			'audit-export'                      => __( 'Prints events as hash-chained JSON lines (--days, --all), like the webhook sends them.', 'sentinel-shield' ),
			'audit-test'                        => __( 'Sends a test through every alert channel: email, webhook, heartbeat, syslog.', 'sentinel-shield' ),
			'health'                            => __( 'Whether protection is actually working (enforcing or test mode, locks, scheduled jobs, blocklists, scans); exits with code 1 on a problem, for monitoring.', 'sentinel-shield' ),
			'scan'                              => __( 'Runs the whole malware scan at once (no time limit) and lists files it could only partly read; exits with code 1 when there are alerts, for monitoring.', 'sentinel-shield' ),
			'verify'                            => __( 'Verifies core and plugin files against WordPress.org checksums now; --coverage lists every item with its result. Exits with code 1 when files differ.', 'sentinel-shield' ),
			'admins'                            => __( 'Lists every administrator account from the database, with hidden and approved flags.', 'sentinel-shield' ),
			'approve-admin <user>'              => __( 'Approves an administrator (ID, login or email). Also the way back in when locked out.', 'sentinel-shield' ),
			'revoke-admin <user>'               => __( 'Withdraws an approval.', 'sentinel-shield' ),
			'unlock-link <user>'                => __( 'Creates a one-time unlock link for an administrator; --email also sends it.', 'sentinel-shield' ),
			'events'                            => __( 'Shows recent security events.', 'sentinel-shield' ),
			'flush-cache / prune'               => __( 'Rebuilds the rule cache, or removes expired rules, old events and used tokens.', 'sentinel-shield' ),
		);
		foreach ( $rows as $cmd => $text ) {
			echo '<tr><td><code>' . esc_html( 'wp sentinel ' . $cmd ) . '</code></td><td>' . esc_html( $text ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * One documentation subsection.
	 *
	 * @param string       $title      Heading.
	 * @param list<string> $paragraphs Paragraphs.
	 */
	private function section( string $title, array $paragraphs ): void {
		echo '<h3>' . esc_html( $title ) . '</h3>';
		foreach ( $paragraphs as $text ) {
			echo '<p>' . esc_html( $text ) . '</p>';
		}
	}

	/**
	 * Human-readable setting value.
	 *
	 * @param array<string, mixed> $field Field.
	 * @param mixed                $value Value.
	 */
	public static function value_text( array $field, mixed $value ): string {
		if ( 'checkbox' === $field['type'] ) {
			return $value ? __( 'On', 'sentinel-shield' ) : __( 'Off', 'sentinel-shield' );
		}
		if ( 'select' === $field['type'] ) {
			return (string) ( $field['options'][ (string) $value ] ?? $value );
		}
		if ( '' === (string) $value ) {
			return __( '(empty)', 'sentinel-shield' );
		}
		return (string) $value;
	}
}
