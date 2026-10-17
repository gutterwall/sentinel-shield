<?php
/**
 * Declarative settings schema: drives the settings UI, sanitization, import and WP-CLI.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield;

use SentinelShield\Feeds\FeedCatalog;
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
			'blocklists'   => __( 'Blocklists', 'sentinel-shield' ),
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
				'help'        => __( 'One per line. IPv4, IPv6 and CIDR ranges allowed; # starts a comment. For the load balancer preset, an empty list trusts private network ranges. For Cloudflare, add any proxy that sits between Cloudflare and this server.', 'sentinel-shield' ),
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
				__( 'The scan runs twice a day. New critical findings and warnings are logged; with this on they are also emailed to the site admin address.', 'sentinel-shield' ),
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
