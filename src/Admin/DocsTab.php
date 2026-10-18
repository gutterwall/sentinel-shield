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
		echo '<p class="description">' . esc_html( sprintf( __( 'Sentinel Shield %s. The same reference is in readme.txt in the plugin folder.', 'sentinel-shield' ), SENTINEL_SHIELD_VERSION ) ) . '</p></div>';

		$this->admins();
		$this->login();
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
				__( 'Usernames on the instant lockout list (such as admin, when no account uses it) lock an IP out at its first try. Turning off XML-RPC logins closes the most common brute-force target if nothing on the site needs it.', 'sentinel-shield' ),
				__( 'Test mode: logins over a limit are allowed and logged as "would deny login", and lockouts are logged as "would lock out". The Login Security tab lists the IPs and accounts with the most failed logins in the last 24 hours.', 'sentinel-shield' ),
			)
		);
		$this->section(
			__( 'Two-factor authentication', 'sentinel-shield' ),
			array(
				__( 'After a correct password, accounts with two-factor authentication are asked for a code before they are logged in. No login cookie exists until the code is right. The code screen lasts 10 minutes and allows five tries; each wrong code counts as a failed login for the brute-force limits.', 'sentinel-shield' ),
				__( 'Methods, set up by each user under Users → Two-Factor Authentication: an authenticator app (any app that supports time-based codes; the QR code is drawn by this site, so the secret never leaves it), codes by email (8 digits, valid 10 minutes, if this site allows them), and ten one-time backup codes for a lost phone. Authenticator secrets are encrypted with keys from wp-config.php; backup and email codes are stored only as keyed hashes.', 'sentinel-shield' ),
				__( 'Requiring it: "Required for administrator-level accounts" (recommended) or "for every account". An account that is required to use it but has no authenticator app gets a code by email at each login and a reminder in the dashboard until it sets one up. If email codes are off, such accounts can still log in with only their password and see the reminder. Check that this site can send email before requiring it.', 'sentinel-shield' ),
				__( 'XML-RPC and the REST API cannot show a code screen, so password logins there are refused for two-factor accounts. Application passwords (Users → Profile) keep working: they are separate, revocable secrets that only a logged-in user can create.', 'sentinel-shield' ),
				__( 'If an administrator changes the security keys and salts in wp-config.php, stored authenticator secrets can no longer be read. Those users log in with a backup or email code and set up their app again; an account with no other method needs a reset.', 'sentinel-shield' ),
				__( 'Lost phone: use a backup code, or an email code if allowed. Otherwise another administrator ticks "Reset two-factor authentication" on the user\'s profile, or run wp sentinel 2fa <user> --reset. "Trust this browser" (if offered) skips the code on that browser for the chosen number of days; users can forget all trusted browsers on their page.', 'sentinel-shield' ),
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
			array( __( 'Your IP is blocked', 'sentinel-shield' ), __( 'wp sentinel unblock <ip> --allow-hours=24, or "Send unlock link" on the block page (403 mode, Emailed unlock links module on), or the SENTINEL_SHIELD_DISABLE constant.', 'sentinel-shield' ) ),
			array( __( 'Your administrator rights are suspended', 'sentinel-shield' ), __( 'Ask an approved administrator to approve you, or run wp sentinel approve-admin <your login>. If SENTINEL_SHIELD_ADMINS is defined, add your login#ID to it in wp-config.php instead. As a last resort, use the SENTINEL_SHIELD_DISABLE constant and approve yourself from the Malware Lockdown page, then remove the constant.', 'sentinel-shield' ) ),
			array( __( 'Your login is refused because of your location', 'sentinel-shield' ), __( 'Add your IP to the allowlist with wp sentinel allow <ip>, or change the countries with wp sentinel settings-set geo.countries "US, CA" (or geo.mode off). The SENTINEL_SHIELD_DISABLE constant also works. Check where an IP is with wp sentinel geo <ip>.', 'sentinel-shield' ) ),
			array( __( 'Too many failed logins', 'sentinel-shield' ), __( 'Wait for the lockout to end, or run wp sentinel unblock <ip> and wp sentinel login-attempts --clear --ip=<ip>. If your account is protected after an attack, log in from an IP you used before, or clear it with wp sentinel login-attempts --clear --account=<login>.', 'sentinel-shield' ) ),
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
			'scan'                              => __( 'Runs the malware scan; exits with code 1 when there are alerts, for monitoring.', 'sentinel-shield' ),
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
