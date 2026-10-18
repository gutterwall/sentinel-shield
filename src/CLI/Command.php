<?php
/**
 * WP-CLI commands: wp sentinel <subcommand>.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\CLI;

defined( 'ABSPATH' ) || exit;

use SentinelShield\Container;
use SentinelShield\Cron\CronInspector;
use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Geo\CountryList;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Audit\AuditExporter;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Modules\LockdownModule;
use SentinelShield\Modules\LockoutModule;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Unlock\UnlockService;
use WP_CLI;
use SentinelShield\Safety\Health;

/**
 * Manage Sentinel Shield. WP-CLI requests are never blocked.
 */
final class Command {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Registers the command.
	 *
	 * @param Container $c Services.
	 */
	public static function register( Container $c ): void {
		WP_CLI::add_command( 'sentinel', new self( $c ) );
	}

	/**
	 * Shows protection status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel status
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function status( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );
		$s     = $this->c->get( Settings::class );
		$rules = $this->c->get( BlockRepository::class );
		$until = (int) $s->get( 'general.test_mode_until', 0 );
		$rows  = array(
			array(
				'Key'   => 'enabled',
				'Value' => $s->get( 'general.enabled' ) ? 'yes' : 'no',
			),
			array(
				'Key'   => 'emergency_disable_constant',
				'Value' => SafetyGuard::emergency_disabled() ? 'SET (blocking off)' : 'not set',
			),
			array(
				'Key'   => 'test_mode',
				'Value' => $s->global_test_mode() ? ( $until ? 'on until ' . wp_date( 'Y-m-d H:i', $until ) : 'on' ) : 'off',
			),
			array(
				'Key'   => 'test_mode_scope',
				'Value' => (string) $s->get( 'general.test_mode_scope' ),
			),
			array(
				'Key'   => 'proxy_mode',
				'Value' => (string) $s->get( 'proxy.mode' ),
			),
			array(
				'Key'   => 'block_rules_active',
				'Value' => (string) $rules->count_active( 'block' ),
			),
			array(
				'Key'   => 'allow_rules_active',
				'Value' => (string) $rules->count_active( 'allow' ),
			),
			array(
				'Key'   => 'lockout_ladder_seconds',
				'Value' => implode( ',', $s->lockout_durations() ),
			),
		);
		foreach ( Settings::MODULES as $module ) {
			$rows[] = array(
				'Key'   => 'module:' . $module,
				'Value' => ( $s->is_module_enabled( $module ) ? 'on' : 'off' ) . ( $s->is_test_mode( $module ) ? ' (test mode)' : '' ),
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'Key', 'Value' ) );
	}

	/**
	 * Simulates the gate decision for an IP (ignores the CLI bypass).
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : IP address to test.
	 *
	 * [--uri=<uri>]
	 * : Request path. Default: /
	 *
	 * [--ignore-allowlist]
	 * : Evaluate as if the IP were not allowlisted.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel check 203.0.113.10 --uri=/wp-login.php
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function check( array $args, array $assoc_args ): void {
		$gate = $this->c->get( Gate::class );
		$d    = $gate->evaluate( $args[0], (string) ( $assoc_args['uri'] ?? '/' ), isset( $assoc_args['ignore-allowlist'] ), true );
		WP_CLI::log( 'Decision: ' . strtoupper( $d->action ) . ( '' !== $d->reason ? ' (' . $d->reason . ')' : '' ) );
		if ( $d->is_block() ) {
			$source = (string) ( $d->rule['source'] ?? 'manual' );
			WP_CLI::log( 'Rule: ' . ( $d->rule['label'] ?? '' ) . ' [source: ' . $source . ']' );
			WP_CLI::log( $gate->is_test_for_source( $source ) ? 'Test mode: would only be logged.' : 'Would be enforced.' );
		}
	}

	/**
	 * Resolves a client IP from simulated REMOTE_ADDR and headers.
	 *
	 * ## OPTIONS
	 *
	 * --remote-addr=<ip>
	 * : Simulated REMOTE_ADDR.
	 *
	 * [--headers=<headers>]
	 * : Headers separated by "|", e.g. "X-Forwarded-For: 1.2.3.4, 10.0.0.2|CF-Connecting-IP: 1.2.3.4".
	 *
	 * [--mode=<mode>]
	 * : Override the proxy preset.
	 * ---
	 * options:
	 *   - none
	 *   - cloudflare
	 *   - load_balancer
	 *   - custom
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel resolve-ip --remote-addr=173.245.48.5 --headers="CF-Connecting-IP: 198.51.100.4" --mode=cloudflare
	 *
	 * @subcommand resolve-ip
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function resolve_ip( array $args, array $assoc_args ): void {
		unset( $args );
		$server = array( 'REMOTE_ADDR' => (string) $assoc_args['remote-addr'] );
		foreach ( explode( '|', (string) ( $assoc_args['headers'] ?? '' ) ) as $pair ) {
			$parts = explode( ':', $pair, 2 );
			if ( 2 === count( $parts ) && '' !== trim( $parts[0] ) ) {
				$server[ 'HTTP_' . strtoupper( str_replace( '-', '_', trim( $parts[0] ) ) ) ] = trim( $parts[1] );
			}
		}
		$proxy = (array) $this->c->get( Settings::class )->get( 'proxy' );
		if ( isset( $assoc_args['mode'] ) ) {
			$proxy['mode'] = $assoc_args['mode'];
		}
		$details = $this->c->get( ClientIpFactory::class )->create( $server, $proxy )->details();
		$rows    = array();
		foreach ( $details as $key => $value ) {
			$rows[] = array(
				'Key'   => $key,
				'Value' => is_bool( $value ) ? ( $value ? 'yes' : 'no' ) : (string) $value,
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'Key', 'Value' ) );
	}

	/**
	 * Blocks an IP or CIDR range.
	 *
	 * ## OPTIONS
	 *
	 * <value>
	 * : IP, CIDR or IPv6.
	 *
	 * [--reason=<reason>]
	 * : Reason.
	 *
	 * [--minutes=<minutes>]
	 * : Expire after N minutes. Default: never.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel block 198.51.100.0/24 --reason="Scanner" --minutes=1440
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function block( array $args, array $assoc_args ): void {
		$this->add_rule( 'block', $args[0], $assoc_args );
	}

	/**
	 * Adds an IP or CIDR range to the allowlist.
	 *
	 * ## OPTIONS
	 *
	 * <value>
	 * : IP, CIDR or IPv6.
	 *
	 * [--reason=<reason>]
	 * : Reason.
	 *
	 * [--minutes=<minutes>]
	 * : Expire after N minutes. Default: never.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel allow 2001:db8::/48 --reason="Office"
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function allow( array $args, array $assoc_args ): void {
		$this->add_rule( 'allow', $args[0], $assoc_args );
	}

	/**
	 * Shared block/allow implementation.
	 *
	 * @param string                $type       List type.
	 * @param string                $value      IP or CIDR.
	 * @param array<string, string> $assoc_args Named.
	 */
	private function add_rule( string $type, string $value, array $assoc_args ): void {
		$cidr = Cidr::parse( $value );
		if ( null === $cidr ) {
			WP_CLI::error( "'$value' is not a valid IP or CIDR range." );
		}
		$minutes = (int) ( $assoc_args['minutes'] ?? 0 );
		$id      = $this->c->get( BlockRepository::class )->add(
			$type,
			$cidr,
			(string) ( $assoc_args['reason'] ?? 'Added via WP-CLI' ),
			'cli',
			$minutes > 0 ? time() + ( $minutes * MINUTE_IN_SECONDS ) : null
		);
		$this->c->get( RuleCache::class )->flush();
		$this->audit(
			'rule_added',
			array(
				'id'   => $id,
				'type' => $type,
				'rule' => $cidr->to_string(),
			)
		);
		WP_CLI::success( sprintf( '%s rule #%d: %s', ucfirst( $type ), $id, $cidr->to_string() ) );
	}

	/**
	 * Unblocks an IP: removes single-IP blocks and clears its lockout history.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP to unblock.
	 *
	 * [--include-ranges]
	 * : Also delete CIDR block rules that contain the IP.
	 *
	 * [--allow-hours=<hours>]
	 * : Add a temporary allowlist entry. Default: 0 (none).
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel unblock 203.0.113.10
	 *     wp sentinel unblock 203.0.113.10 --include-ranges --allow-hours=24
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function unblock( array $args, array $assoc_args ): void {
		$result = $this->c->get( Unblocker::class )->unblock( $args[0], isset( $assoc_args['include-ranges'] ), (int) ( $assoc_args['allow-hours'] ?? 0 ), 0, 'cli' );
		if ( null === $result ) {
			WP_CLI::error( 'Provide a single valid IP address.' );
		}
		WP_CLI::success( sprintf( 'Removed %d block rule(s) for %s; lockout history cleared.', $result['removed'], $args[0] ) );
		if ( $result['ranges'] ) {
			WP_CLI::warning( 'Still covered by range rules: ' . implode( ', ', $result['ranges'] ) . '. Use --include-ranges or --allow-hours.' );
		}
		if ( $result['allowed'] ) {
			WP_CLI::log( 'Temporary allowlist entry added.' );
		}
	}

	/**
	 * Deletes a rule by ID.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Rule ID (see `wp sentinel list`).
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function remove( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$repo = $this->c->get( BlockRepository::class );
		$rule = $repo->get( (int) $args[0] );
		if ( null === $rule || ! $repo->delete( (int) $args[0] ) ) {
			WP_CLI::error( 'Rule not found.' );
		}
		$this->c->get( RuleCache::class )->flush();
		$this->audit(
			'rule_removed',
			array(
				'id'   => (int) $args[0],
				'rule' => $rule['label'],
			)
		);
		WP_CLI::success( 'Removed rule ' . $rule['label'] );
	}

	/**
	 * Lists rules.
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : block or allow.
	 *
	 * [--search=<search>]
	 * : IP/CIDR (containment) or text.
	 *
	 * [--include-expired]
	 * : Include expired rules.
	 *
	 * [--format=<format>]
	 * : table, csv, json, yaml, count. Default: table.
	 *
	 * @subcommand list
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function list_( array $args, array $assoc_args ): void {
		unset( $args );
		[ $rows ] = $this->c->get( BlockRepository::class )->query(
			array(
				'type'            => (string) ( $assoc_args['type'] ?? '' ),
				'search'          => (string) ( $assoc_args['search'] ?? '' ),
				'include_expired' => isset( $assoc_args['include-expired'] ),
				'per_page'        => 1000,
			)
		);
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'id', 'label', 'list_type', 'reason', 'source', 'created_at', 'expires_at', 'hits' ) );
	}

	/**
	 * Applies a lockout to an IP using the real progressive logic (respects test mode).
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP.
	 *
	 * [--module=<module>]
	 * : Module name to record. Default: test
	 *
	 * [--reason=<reason>]
	 * : Reason.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel lockout 203.0.113.10
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function lockout( array $args, array $assoc_args ): void {
		$lockout = LockoutModule::apply( $this->c, $args[0], (string) ( $assoc_args['module'] ?? 'test' ), (string) ( $assoc_args['reason'] ?? 'Lockout via WP-CLI' ) );
		if ( null === $lockout ) {
			WP_CLI::error( 'Not locked out: invalid IP, allowlisted, this server, or the lockout module is disabled.' );
		}
		WP_CLI::success(
			sprintf(
				'%s: step %d, %s%s',
				$lockout->ip,
				$lockout->step,
				$lockout->is_permanent() ? 'permanent' : $lockout->duration . 's',
				$lockout->is_test ? ' (TEST MODE: logged only)' : ''
			)
		);
	}

	/**
	 * Turns test mode on or off, or shows it.
	 *
	 * ## OPTIONS
	 *
	 * <state>
	 * : on, off or status.
	 * ---
	 * options:
	 *   - on
	 *   - off
	 *   - status
	 * ---
	 *
	 * [--hours=<hours>]
	 * : With "on": end test mode automatically after N hours.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel test-mode on --hours=24
	 *     wp sentinel test-mode off
	 *
	 * @subcommand test-mode
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function test_mode( array $args, array $assoc_args ): void {
		$settings = $this->c->get( Settings::class );
		if ( 'status' === $args[0] ) {
			WP_CLI::log( $settings->global_test_mode() ? 'Test mode is ON.' : 'Test mode is OFF (enforcing).' );
			return;
		}
		$all                               = $settings->network_settings();
		$all['general']['test_mode']       = 'on' === $args[0];
		$all['general']['test_mode_hours'] = 'on' === $args[0] ? max( 0, min( 720, (int) ( $assoc_args['hours'] ?? 0 ) ) ) : 0;
		$settings->save_network( Settings::apply_test_mode_expiry( $all ) );
		$this->audit( 'test_mode:' . $args[0] );
		WP_CLI::success( 'on' === $args[0] ? 'Test mode on.' : 'Test mode off: blocking is enforced.' );
	}

	/**
	 * Prints a setting, or all settings as JSON.
	 *
	 * ## OPTIONS
	 *
	 * [<path>]
	 * : Dot path, e.g. general.test_mode
	 *
	 * @subcommand settings-get
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function settings_get( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$all = $this->c->get( Settings::class )->network_settings();
		$out = isset( $args[0] ) ? Settings::get_path( $all, $args[0] ) : $all;
		WP_CLI::log( (string) wp_json_encode( $out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
	}

	/**
	 * Sets any setting by dot path (validated against the schema).
	 *
	 * ## OPTIONS
	 *
	 * <path>
	 * : Dot path. Run `wp sentinel settings-keys` for the list.
	 *
	 * <value>
	 * : New value. Booleans: 1/0, true/false, on/off. Lists: use "\n" or commas.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel settings-set proxy.mode cloudflare
	 *     wp sentinel settings-set lockout.step1_minutes 5
	 *     wp sentinel settings-set modules.lockout.test_mode off
	 *
	 * @subcommand settings-set
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function settings_set( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$field = SettingsSchema::field( $args[0] );
		if ( null === $field ) {
			WP_CLI::error( "Unknown setting '{$args[0]}'. Run: wp sentinel settings-keys" );
		}
		$raw               = 'cidr_list' === $field['type'] ? str_replace( array( '\n', ',' ), "\n", $args[1] ) : $args[1];
		[ $value, $error ] = SettingsSchema::sanitize_field( $field, $raw );
		if ( null !== $error ) {
			WP_CLI::warning( $error );
		}
		$settings = $this->c->get( Settings::class );
		$all      = $settings->network_settings();
		Settings::set_path( $all, $args[0], $value );
		if ( in_array( $args[0], array( 'general.test_mode', 'general.test_mode_hours' ), true ) ) {
			$all = Settings::apply_test_mode_expiry( $all );
		}
		$settings->save_network( $all );
		$this->audit( 'settings:' . $args[0] );
		WP_CLI::success( $args[0] . ' = ' . wp_json_encode( $value ) );
	}

	/**
	 * Lists every configurable setting with its type and recommended value.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, csv, json, yaml. Default: table.
	 *
	 * @subcommand settings-keys
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function settings_keys( array $args, array $assoc_args ): void {
		unset( $args );
		$all  = $this->c->get( Settings::class )->network_settings();
		$rows = array();
		foreach ( SettingsSchema::fields() as $field ) {
			$current = Settings::get_path( $all, (string) $field['key'] );
			$rows[]  = array(
				'key'         => $field['key'],
				'type'        => $field['type'] . ( 'select' === $field['type'] ? ' (' . implode( '|', array_keys( (array) $field['options'] ) ) . ')' : '' ),
				'current'     => is_bool( $current ) ? ( $current ? '1' : '0' ) : str_replace( "\n", ', ', (string) $current ),
				'recommended' => is_bool( $field['recommended'] ) ? ( $field['recommended'] ? '1' : '0' ) : (string) $field['recommended'],
			);
		}
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'key', 'type', 'current', 'recommended' ) );
	}

	/**
	 * Exports settings to a JSON file (or stdout).
	 *
	 * ## OPTIONS
	 *
	 * [<file>]
	 * : Output file.
	 *
	 * @subcommand settings-export
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function settings_export( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$json = (string) wp_json_encode(
			array(
				'plugin'   => 'sentinel-shield',
				'version'  => SENTINEL_SHIELD_VERSION,
				'exported' => gmdate( 'c' ),
				'settings' => $this->c->get( Settings::class )->network_settings(),
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		);
		if ( isset( $args[0] ) ) {
			file_put_contents( $args[0], $json ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			WP_CLI::success( 'Written to ' . $args[0] );
			return;
		}
		WP_CLI::log( $json );
	}

	/**
	 * Imports settings from a JSON file.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : JSON file from settings-export or the admin.
	 *
	 * @subcommand settings-import
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function settings_import( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		if ( ! is_readable( $args[0] ) ) {
			WP_CLI::error( 'File not readable.' );
		}
		$data = json_decode( (string) file_get_contents( $args[0] ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( ! is_array( $data ) ) {
			WP_CLI::error( 'Invalid JSON.' );
		}
		[ $clean, $errors ] = SettingsSchema::sanitize_all( isset( $data['settings'] ) && is_array( $data['settings'] ) ? $data['settings'] : $data );
		foreach ( $errors as $error ) {
			WP_CLI::warning( $error );
		}
		$this->c->get( Settings::class )->save_network( $clean );
		$this->audit( 'settings_imported' );
		WP_CLI::success( 'Settings imported.' );
	}

	/**
	 * Downloads the latest Cloudflare IP ranges.
	 *
	 * @subcommand cloudflare-update
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function cloudflare_update( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );
		$result = $this->c->get( CloudflareRanges::class )->refresh();
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		WP_CLI::success( count( $this->c->get( CloudflareRanges::class )->all() ) . ' Cloudflare ranges stored.' );
	}

	/**
	 * Clears the compiled rule cache.
	 *
	 * @subcommand flush-cache
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function flush_cache( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );
		$cache = $this->c->get( RuleCache::class );
		$cache->flush();
		$cache->flush_feeds();
		WP_CLI::success( 'Rule cache cleared.' );
	}

	/**
	 * Lists scheduled WP-Cron tasks with next run, last recorded run and the code they call.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * [--failed]
	 * : Only tasks whose last recorded run failed.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel cron
	 *     wp sentinel cron --failed --format=json
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function cron( array $args, array $assoc_args ): void {
		unset( $args );
		$when = static fn( int $t ): string => $t > 0 ? gmdate( 'Y-m-d H:i:s', $t ) . ' UTC' : '';
		$rows = array();
		foreach ( CronInspector::events() as $event ) {
			$run = is_array( $event['run'] ) ? $event['run'] : null;
			if ( isset( $assoc_args['failed'] ) && ( null === $run || 'ok' === $run['status'] ) ) {
				continue;
			}
			$code = array();
			foreach ( $event['callbacks'] as $cb ) {
				$code[] = $cb['name'] . ' [' . $cb['source'] . ']';
			}
			$rows[] = array(
				'hook'      => $event['hook'],
				'args'      => $event['args'] ? (string) wp_json_encode( $event['args'] ) : '',
				'repeats'   => $event['recurs'],
				'next_run'  => $when( (int) $event['next_run'] ) . ( $event['next_run'] < time() - CronInspector::OVERDUE_AFTER ? ' (overdue)' : '' ),
				'last_run'  => null === $run ? 'not seen yet' : $when( (int) $run['last_start'] ),
				'status'    => null === $run ? '' : ( 'ok' === $run['status'] ? 'completed' : 'failed: ' . $run['error'] ),
				'duration'  => null === $run ? '' : $run['duration'] . 's',
				'callbacks' => $code ? implode( '; ', $code ) : '(none)',
				'command'   => CronInspector::command( $event['hook'] ),
			);
		}
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'hook', 'args', 'repeats', 'next_run', 'last_run', 'status', 'duration', 'callbacks', 'command' ) );
	}

	/**
	 * Shows the public blocklist feeds and their update status.
	 *
	 * Enable a list with: wp sentinel settings-set feeds.lists.<slug> 1
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel feeds
	 *     wp sentinel settings-set feeds.lists.spamhaus_drop 1
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function feeds( array $args, array $assoc_args ): void {
		unset( $args );
		$updater = $this->c->get( FeedUpdater::class );
		$state   = $updater->state();
		$enabled = $updater->enabled();
		$when    = static fn( int $t ): string => $t > 0 ? gmdate( 'Y-m-d H:i', $t ) . ' UTC' : '';
		$rows    = array();
		foreach ( FeedCatalog::all() as $slug => $feed ) {
			$entry  = $state[ $slug ] ?? array();
			$on     = in_array( $slug, $enabled, true );
			$rows[] = array(
				'slug'         => $slug,
				'name'         => $feed['name'],
				'enabled'      => $on ? 'yes' : 'no',
				'terms'        => $feed['terms'],
				'ranges'       => $on ? (int) ( $entry['count'] ?? 0 ) : '',
				'last_checked' => $on ? $when( (int) ( $entry['last_check'] ?? 0 ) ) : '',
				'last_changed' => $on ? $when( (int) ( $entry['last_change'] ?? 0 ) ) : '',
				'next_check'   => $on ? $when( (int) ( $entry['next_due'] ?? 0 ) ) : '',
				'error'        => (string) ( $entry['error'] ?? '' ),
			);
		}
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'slug', 'name', 'enabled', 'terms', 'ranges', 'last_checked', 'last_changed', 'next_check', 'error' ) );
	}

	/**
	 * Downloads enabled blocklist feeds now.
	 *
	 * ## OPTIONS
	 *
	 * [<slug>...]
	 * : Feeds to update. Default: all enabled feeds.
	 *
	 * [--force]
	 * : Download in full even if the provider reports no change.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel feeds-update
	 *     wp sentinel feeds-update spamhaus_drop --force
	 *
	 * @subcommand feeds-update
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function feeds_update( array $args, array $assoc_args ): void {
		$updater = $this->c->get( FeedUpdater::class );
		$enabled = $updater->enabled();
		$slugs   = $args ? $args : $enabled;
		if ( ! $slugs ) {
			WP_CLI::error( 'No blocklist feeds are enabled. Enable one with: wp sentinel settings-set feeds.lists.<slug> 1' );
		}
		$failed = 0;
		foreach ( $slugs as $slug ) {
			if ( ! in_array( $slug, $enabled, true ) ) {
				WP_CLI::warning( "$slug is not an enabled feed; skipped." );
				++$failed;
				continue;
			}
			$result = $updater->update( $slug, isset( $assoc_args['force'] ) );
			if ( is_wp_error( $result ) ) {
				WP_CLI::warning( "$slug: " . $result->get_error_message() );
				++$failed;
				continue;
			}
			$entry = $updater->state()[ $slug ] ?? array();
			WP_CLI::log( sprintf( '%s: %d ranges (%d entries skipped as invalid or reserved).', $slug, (int) ( $entry['count'] ?? 0 ), (int) ( $entry['skipped'] ?? 0 ) ) );
		}
		if ( $failed ) {
			WP_CLI::error( "$failed feed(s) failed; previous copies were kept." );
		}
		WP_CLI::success( 'Blocklist feeds updated.' );
	}

	/**
	 * Shows an IP's country and whether a login from it would be allowed.
	 *
	 * Uses the local DB-IP database (the Cloudflare header and server variable
	 * only exist for web requests).
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : IP address.
	 *
	 * [--account=<user>]
	 * : Account to check (ID, login or email); matters when the restriction applies to administrators only.
	 *
	 * [--format=<format>]
	 * : table, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel geo 8.8.8.8
	 *     wp sentinel geo 203.0.113.7 --account=admin
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function geo( array $args, array $assoc_args ): void {
		$ip = (string) IpAddress::normalize( $args[0] );
		if ( '' === $ip ) {
			WP_CLI::error( "Not a valid IP address: {$args[0]}" );
		}
		$user  = isset( $assoc_args['account'] ) ? $this->find_user( (string) $assoc_args['account'] ) : null;
		$check = $this->c->get( LoginGeoGuard::class )->check( $ip, $user );
		$geo   = '' === $check['source'] ? $this->c->get( GeoResolver::class )->resolve( $ip ) : $check;
		$row   = array(
			'ip'      => $ip,
			'country' => '' === $geo['country'] ? 'unknown' : CountryList::label( $geo['country'] ),
			'source'  => $geo['source'],
			'login'   => $check['allowed'] ? 'allowed' : 'denied',
			'reason'  => LoginGeoGuard::explain( $check ),
		);
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), array( $row ), array_keys( $row ) );
	}

	/**
	 * Downloads the DB-IP country database now.
	 *
	 * ## OPTIONS
	 *
	 * [--force]
	 * : Download even if unchanged.
	 *
	 * @subcommand geo-update
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function geo_update( array $args, array $assoc_args ): void {
		unset( $args );
		if ( ! $this->c->get( Settings::class )->get( 'geo.dbip', false ) ) {
			WP_CLI::error( 'DB-IP downloads are off. Enable them with: wp sentinel settings-set geo.dbip 1' );
		}
		$result = $this->c->get( GeoUpdater::class )->update( isset( $assoc_args['force'] ) );
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() . ' The previous database (if any) was kept.' );
		}
		WP_CLI::success( sprintf( 'Country database %s: %d IPv4 and %d IPv6 ranges. IP Geolocation by DB-IP (https://db-ip.com).', (string) ( $result['month'] ?? '?' ), (int) ( $result['v4'] ?? 0 ), (int) ( $result['v6'] ?? 0 ) ) );
	}

	/**
	 * Shows two-factor status, or resets an account's two-factor authentication.
	 *
	 * Without a user, lists administrator-level accounts and every account with
	 * a method set up. --reset removes the authenticator app, email codes, backup
	 * codes and trusted browsers (the way back in after a lost phone).
	 *
	 * ## OPTIONS
	 *
	 * [<user>]
	 * : User ID, login or email.
	 *
	 * [--reset]
	 * : Remove every two-factor method of the user.
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel 2fa
	 *     wp sentinel 2fa jane --reset
	 *
	 * @subcommand 2fa
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function two_factor( array $args, array $assoc_args ): void {
		$users = $this->c->get( UserTwoFactor::class );
		$login = $this->c->get( TwoFactorLogin::class );
		if ( isset( $assoc_args['reset'] ) ) {
			if ( ! isset( $args[0] ) ) {
				WP_CLI::error( 'Name the user to reset: wp sentinel 2fa <user> --reset' );
			}
			$user = $this->find_user( $args[0] );
			$users->reset( (int) $user->ID );
			$this->audit( 'twofa_reset:' . $user->user_login, array( 'user_id' => $user->ID ) );
			WP_CLI::success( "Two-factor authentication reset for {$user->user_login}." . ( $login->required( $user ) && $login->email_allowed() ? ' It is required for this account, so login codes will be emailed until a new app is set up.' : '' ) );
			return;
		}
		if ( isset( $args[0] ) ) {
			$list = array( $this->find_user( $args[0] ) );
		} else {
			$ids  = array_map( static fn( array $u ): int => (int) $u['id'], $this->c->get( AdminRegistry::class )->privileged_users() );
			$ids  = array_merge(
				$ids,
				get_users(
					array(
						'fields'       => 'ID',
						'blog_id'      => 0,
						'meta_key'     => UserTwoFactor::META . 'totp', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Admin listing.
						'meta_compare' => 'EXISTS',
					)
				),
				get_users(
					array(
						'fields'   => 'ID',
						'blog_id'  => 0,
						'meta_key' => UserTwoFactor::META . 'email', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Admin listing.
					)
				)
			);
			$list = array_filter( array_map( 'get_userdata', array_unique( array_map( 'intval', $ids ) ) ) );
		}
		$rows = array();
		foreach ( $list as $user ) {
			$summary = $users->summary( (int) $user->ID );
			$rows[]  = array(
				'id'       => $user->ID,
				'login'    => $user->user_login,
				'app'      => $summary['totp'] ? ( $summary['totp_readable'] ? 'yes' : 'UNREADABLE' ) : 'no',
				'email'    => $summary['email'] ? 'yes' : 'no',
				'backup'   => $summary['backup'],
				'required' => $login->required( $user ) ? 'yes' : 'no',
				'at_login' => $login->locked_out( $user ) ? 'refused (no method)' : ( $login->needs_second_step( $user ) ? 'code' : 'password only' ),
			);
		}
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'id', 'login', 'app', 'email', 'backup', 'required', 'at_login' ) );
	}

	/**
	 * Shows failed logins by IP and account, or forgets them.
	 *
	 * ## OPTIONS
	 *
	 * [--clear]
	 * : Forget failed logins (all, or only those of --ip / --account).
	 *
	 * [--ip=<ip>]
	 * : One IP: show whether a login from it is allowed now.
	 *
	 * [--account=<user>]
	 * : One account (login, email or a name that matches no account).
	 *
	 * [--hours=<hours>]
	 * : How far back to list.
	 * ---
	 * default: 24
	 * ---
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel login-attempts
	 *     wp sentinel login-attempts --ip=203.0.113.7
	 *     wp sentinel login-attempts --clear --account=admin
	 *
	 * @subcommand login-attempts
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function login_attempts( array $args, array $assoc_args ): void {
		unset( $args );
		$repo  = $this->c->get( LoginAttemptRepository::class );
		$guard = $this->c->get( BruteForceGuard::class );
		$ip    = isset( $assoc_args['ip'] ) ? (string) IpAddress::normalize( (string) $assoc_args['ip'] ) : '';
		if ( isset( $assoc_args['ip'] ) && '' === $ip ) {
			WP_CLI::error( "Not a valid IP address: {$assoc_args['ip']}" );
		}
		$name = (string) ( $assoc_args['account'] ?? '' );
		if ( isset( $assoc_args['clear'] ) ) {
			$rows = 0;
			if ( '' !== $ip ) {
				$rows += $repo->clear_ip( (string) IpAddress::to_binary( $ip ) );
			}
			if ( '' !== $name ) {
				$rows += $repo->clear_account( BruteForceGuard::account_key( $name ) );
			}
			if ( '' === $ip && '' === $name ) {
				$rows = $repo->clear_all();
			}
			\SentinelShield\Support\Cached::bump();
			$this->audit( 'login_attempts_cleared', array( 'rows' => $rows ) );
			WP_CLI::success( "Forgot $rows failed logins. Lockouts already applied stay; lift them with wp sentinel unblock <ip>." );
			return;
		}
		$format = (string) ( $assoc_args['format'] ?? 'table' );
		if ( '' !== $ip || '' !== $name ) {
			$check = $guard->check( '' === $ip ? '0.0.0.0' : $ip, $name );
			$since = time() - $guard->window_minutes() * MINUTE_IN_SECONDS;
			$row   = array(
				'ip'               => $ip,
				'ip_failures'      => '' === $ip ? '' : $repo->count_ip( (string) IpAddress::to_binary( $ip ), $since ),
				'account'          => '' === $name ? '' : BruteForceGuard::account_label( BruteForceGuard::account_key( $name ) ),
				'account_failures' => '' === $name ? '' : $repo->count_account( BruteForceGuard::account_key( $name ), $since )['failures'],
				'login'            => '' === $ip ? '' : ( $check['allowed'] ? 'allowed' : 'refused' ),
				'reason'           => '' === $ip ? '' : BruteForceGuard::explain( $check ),
			);
			WP_CLI\Utils\format_items( $format, array( $row ), array_keys( $row ) );
			WP_CLI::log( sprintf( 'Counts cover the last %d minutes (limits: %d per IP, %d per account).', $guard->window_minutes(), $guard->max_failures(), (int) $this->c->get( Settings::class )->get( 'login.account_max_failures', 20 ) ) );
			return;
		}
		$since = time() - max( 1, (int) ( $assoc_args['hours'] ?? 24 ) ) * HOUR_IN_SECONDS;
		$rows  = array();
		foreach ( $repo->top_ips( $since, 20 ) as $r ) {
			$rows[] = array(
				'type'     => 'ip',
				'subject'  => $r['ip'],
				'failures' => $r['failures'],
				'spread'   => $r['accounts'] . ' accounts',
				'last'     => $r['last'],
			);
		}
		foreach ( $repo->top_accounts( $since, 20 ) as $r ) {
			$rows[] = array(
				'type'     => 'account',
				'subject'  => BruteForceGuard::account_label( $r['account'] ),
				'failures' => $r['failures'],
				'spread'   => $r['ips'] . ' IPs',
				'last'     => $r['last'],
			);
		}
		if ( ! $rows && 'table' === $format ) {
			WP_CLI::success( 'No failed logins in that period.' );
			return;
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'type', 'subject', 'failures', 'spread', 'last' ) );
	}

	/**
	 * Prints events as JSON lines with the same hash chain as the webhook.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : How far back.
	 * ---
	 * default: 30
	 * ---
	 *
	 * [--all]
	 * : Include routine blocked requests.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel audit-export --days=7 > events.jsonl
	 *
	 * @subcommand audit-export
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function audit_export( array $args, array $assoc_args ): void {
		unset( $args );
		global $wpdb;
		$table = $this->c->get( \SentinelShield\Repository\EventRepository::class )->table();
		$since = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) ( $assoc_args['days'] ?? 30 ) ) * DAY_IN_SECONDS );
		$last  = 0;
		$seq   = 0;
		$hash  = '';
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Reads the event table in pages.
			$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT id, created_at, ip_text, event, module, reason, uri, user_agent, user_id, is_test, context FROM %i WHERE id > %d AND created_at >= %s ORDER BY id LIMIT 1000', $table, $last, $since ), ARRAY_A );
			if ( ! $rows ) {
				break;
			}
			$last = (int) end( $rows )['id'];
			if ( ! isset( $assoc_args['all'] ) ) {
				$rows = array_values( array_filter( $rows, static fn( array $r ): bool => ! in_array( $r['event'], AuditExporter::NOISY, true ) ) );
			}
			[ $events, $seq, $hash ] = AuditExporter::chain( $rows, $seq, $hash );
			foreach ( $events as $event ) {
				WP_CLI::line( (string) wp_json_encode( $event ) );
			}
		} while ( true );
	}

	/**
	 * Sends a test alert through every configured channel.
	 *
	 * @subcommand audit-test
	 */
	public function audit_test(): void {
		foreach ( $this->c->get( AuditExporter::class )->test() as $channel => $result ) {
			WP_CLI::log( str_pad( $channel . ':', 11 ) . $result );
		}
	}

	/**
	 * Early firewall status, or rebuild its snapshot (and server files).
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : status (default) or rebuild.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel early-gate
	 *     wp sentinel early-gate rebuild
	 *
	 * @subcommand early-gate
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function early_gate( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$gate = $this->c->get( EarlyGate::class );
		if ( 'rebuild' === ( $args[0] ?? 'status' ) ) {
			if ( ! $gate->wanted() ) {
				WP_CLI::error( 'Nothing uses the snapshot: the early firewall, server files and Cloudflare sync are all off.' );
			}
			$state = $gate->rebuild();
			if ( ! empty( $state['error'] ) ) {
				WP_CLI::error( (string) $state['error'] );
			}
			WP_CLI::success( sprintf( 'Snapshot rebuilt: %d blocked ranges, %d allowlisted, valid until %s.', (int) $state['block'], (int) $state['allow'], wp_date( 'Y-m-d H:i', (int) $state['valid_until'] ) ) );
			return;
		}
		$state = (array) get_site_option( EarlyGate::STATE, array() );
		WP_CLI::log( 'Mode:      ' . $gate->mode() );
		WP_CLI::log( 'Gate file: ' . EarlyGate::gate_file() );
		WP_CLI::log( 'Snapshot:  ' . ( $state ? sprintf( '%s (built %s, valid until %s, %d blocked, %d allowlisted)', EarlyGate::path(), wp_date( 'Y-m-d H:i', (int) $state['built'] ), wp_date( 'Y-m-d H:i', (int) $state['valid_until'] ), (int) $state['block'], (int) $state['allow'] ) : 'none' ) );
		WP_CLI::log( 'Loader:    ' . ( EarlyGate::is_own_loader( EarlyGate::loader_path() ) ? EarlyGate::loader_path() : 'not installed' ) );
		if ( 'prepend' === $gate->mode() ) {
			WP_CLI::log( 'Add one of these lines to the server configuration:' );
			foreach ( EarlyGate::prepend_snippets() as $where => $line ) {
				WP_CLI::log( "  $where: $line" );
			}
		}
	}

	/**
	 * Prints the enforced blocklist for a web server or CDN.
	 *
	 * ## OPTIONS
	 *
	 * <format>
	 * : nginx, apache, text or cloudflare.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel server-export nginx > /etc/nginx/sentinel-deny.conf
	 *
	 * @subcommand server-export
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function server_export( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$data   = $this->c->get( EarlyGate::class )->compile();
		$labels = $data['blocked'];
		switch ( $args[0] ?? '' ) {
			case 'nginx':
				WP_CLI::line( rtrim( EarlyGate::nginx( $labels ) ) );
				break;
			case 'apache':
				WP_CLI::line( rtrim( EarlyGate::apache( $labels ) ) );
				break;
			case 'text':
				WP_CLI::line( implode( "\n", $labels ) );
				break;
			case 'cloudflare':
				$conv = CloudflareSync::items( $labels, (string) $this->c->get( Settings::class )->get( 'cloudflare.ipv6', 'skip' ), $data['allow_set'] );
				WP_CLI::line( implode( "\n", $conv['items'] ) );
				if ( $conv['skipped'] || $conv['expanded'] ) {
					WP_CLI::warning( sprintf( '%d entries left out (Cloudflare lists take IPv6 ranges up to /64 only), %d single IPv6 addresses widened to /64.', $conv['skipped'], $conv['expanded'] ) );
				}
				break;
			default:
				WP_CLI::error( 'Format must be nginx, apache, text or cloudflare.' );
		}
	}

	/**
	 * Syncs the enforced blocklist to the configured Cloudflare IP list now.
	 *
	 * ## OPTIONS
	 *
	 * [--test]
	 * : Only check the connection.
	 *
	 * @subcommand cloudflare-sync
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function cloudflare_sync( array $args, array $assoc_args ): void {
		unset( $args );
		$sync = $this->c->get( CloudflareSync::class );
		if ( isset( $assoc_args['test'] ) ) {
			$result = $sync->test();
			$result['ok'] ? WP_CLI::success( $result['message'] ) : WP_CLI::error( $result['message'] );
			return;
		}
		if ( ! $sync->enabled() ) {
			WP_CLI::error( 'Cloudflare sync is off or not configured (cloudflare.sync, cloudflare.account_id, cloudflare.list_id and a token saved on the Server & CDN tab).' );
		}
		$state = $sync->sync( true );
		empty( $state['ok'] ) ? WP_CLI::error( (string) $state['error'] ) : WP_CLI::success( sprintf( 'Synced %d items.', (int) $state['count'] ) );
	}

	/**
	 * Shows whether protection is actually working: enforcement, locks,
	 * scheduled jobs, blocklists, scans.
	 *
	 * Exits with status 1 when a check reports a problem (for monitoring).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function health( array $args, array $assoc_args ): void {
		unset( $args );
		$checks = ( new Health( $this->c ) )->checks();
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $checks, array( 'state', 'label', 'detail' ) );
		if ( 'bad' === Health::overall( $checks ) ) {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Scans for the persistence points of the SC WordPress malware. Read-only.
	 *
	 * Exits with status 1 when there are critical findings or warnings.
	 *
	 * ## OPTIONS
	 *
	 * [--all]
	 * : Also list items to review and approved items.
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel scan
	 *     wp sentinel scan --all --format=json
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function scan( array $args, array $assoc_args ): void {
		unset( $args );
		// No time or entry limits here: the whole uploads folder is walked in one go.
		delete_site_option( IntegrityScanner::UPLOADS_STATE );
		$report = $this->c->get( IntegrityScanner::class )->run( true );
		LockdownModule::notify( $this->c, $report, false );
		$labels = IntegrityScanner::checks();
		$rows   = array();
		foreach ( $report['findings'] as $finding ) {
			if ( ! isset( $assoc_args['all'] ) && ! IntegrityScanner::is_alert( $finding ) ) {
				continue;
			}
			$rows[] = array(
				'severity' => $finding['severity'],
				'check'    => $labels[ $finding['check'] ][0] ?? $finding['check'],
				'title'    => $finding['title'],
				'detail'   => $finding['detail'],
				'id'       => $finding['id'],
			);
		}
		$format = (string) ( $assoc_args['format'] ?? 'table' );
		if ( $rows || 'table' !== $format ) {
			WP_CLI\Utils\format_items( $format, $rows, array( 'severity', 'check', 'title', 'detail', 'id' ) );
		}
		$alerts = count( array_filter( $report['findings'], array( IntegrityScanner::class, 'is_alert' ) ) );
		if ( $alerts ) {
			WP_CLI::halt( 1 );
		}
		WP_CLI::success( sprintf( 'No critical findings or warnings (%d checks, %d files opened, %.1fs).', count( $labels ), (int) ( $report['coverage']['read'] ?? 0 ), $report['duration'] ) );
		foreach ( (array) ( $report['coverage']['partial'] ?? array() ) as $file ) {
			WP_CLI::warning( sprintf( 'Read only partly (first %s): %s', size_format( IntegrityScanner::max_read() ), $file ) );
		}
		foreach ( (array) ( $report['coverage']['unreadable'] ?? array() ) as $file ) {
			WP_CLI::warning( 'Could not read: ' . $file );
		}
	}

	/**
	 * Verifies WordPress core and plugin files against WordPress.org checksums. Read-only.
	 *
	 * Runs a complete pass now (no time slices). Exits with status 1 when
	 * files differ from WordPress.org.
	 *
	 * ## OPTIONS
	 *
	 * [--coverage]
	 * : List every core, plugin and theme item with its result instead of the findings.
	 *
	 * [--all]
	 * : Also list items to review (missing files) and approved items.
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel verify
	 *     wp sentinel verify --coverage
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function verify( array $args, array $assoc_args ): void {
		unset( $args );
		$report = $this->c->get( FileIntegrity::class )->run_all();
		LockdownModule::notify( $this->c, $report, false, 'integrity' );
		$format = (string) ( $assoc_args['format'] ?? 'table' );
		if ( isset( $assoc_args['coverage'] ) ) {
			$rows = array();
			foreach ( (array) $report['coverage'] as $cov ) {
				$rows[] = array(
					'type'     => $cov['type'],
					'name'     => $cov['name'],
					'version'  => $cov['version'],
					'status'   => $cov['status'],
					'files'    => $cov['files'],
					'modified' => $cov['modified'],
					'extra'    => $cov['extra'],
					'missing'  => $cov['missing_total'] ?? 0,
					'reason'   => '' === (string) $cov['reason'] ? '' : FileIntegrity::reason_text( (string) $cov['reason'] ),
				);
			}
			WP_CLI\Utils\format_items( $format, $rows, array( 'type', 'name', 'version', 'status', 'files', 'modified', 'extra', 'missing', 'reason' ) );
		} else {
			$rows = array();
			foreach ( (array) $report['findings'] as $finding ) {
				if ( isset( $assoc_args['all'] ) || IntegrityScanner::is_alert( $finding ) ) {
					$rows[] = array(
						'severity' => $finding['severity'],
						'item'     => $finding['target'],
						'title'    => $finding['title'],
						'detail'   => $finding['detail'],
						'id'       => $finding['id'],
					);
				}
			}
			if ( $rows || 'table' !== $format ) {
				WP_CLI\Utils\format_items( $format, $rows, array( 'severity', 'item', 'title', 'detail', 'id' ) );
			}
		}
		if ( array_filter( (array) $report['findings'], array( IntegrityScanner::class, 'is_alert' ) ) ) {
			WP_CLI::halt( 1 );
		}
		$counts = array_count_values( array_column( (array) $report['coverage'], 'status' ) );
		WP_CLI::success( sprintf( '%d files match WordPress.org (%d items verified, %d not verifiable; %.1fs).', $report['hashed'], (int) ( $counts['verified'] ?? 0 ), (int) ( $counts['unverifiable'] ?? 0 ), $report['duration'] ) );
	}

	/**
	 * Lists administrator accounts found in the database, with hidden and approval status.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, csv, json or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function admins( array $args, array $assoc_args ): void {
		unset( $args );
		$rows = array();
		foreach ( $this->c->get( AdminRegistry::class )->privileged_users() as $user ) {
			$rows[] = array(
				'id'         => $user['id'],
				'login'      => $user['login'],
				'email'      => $user['email'],
				'registered' => $user['registered'],
				'hidden'     => $user['hidden'] ? 'HIDDEN' : 'no',
				'approved'   => $user['approved'] ? 'yes' : 'no',
			);
		}
		$registry = $this->c->get( AdminRegistry::class );
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'id', 'login', 'email', 'registered', 'hidden', 'approved' ) );
		if ( $registry->is_fixed() ) {
			$entries = array_map( static fn( array $e ): string => $e['entry'] . ( 'ok' === $e['state'] ? '' : ' (' . $e['state'] . ')' ), $registry->fixed_report() );
			WP_CLI::warning( 'Approvals come from SENTINEL_SHIELD_ADMINS in wp-config.php: ' . ( $entries ? implode( ', ', $entries ) : '(empty: every administrator is locked)' ) );
		}
	}

	/**
	 * Approves an administrator account for the administrator lock (also the way back in if you are locked out).
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel approve-admin admin
	 *
	 * @subcommand approve-admin
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function approve_admin( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$user = $this->find_user( $args[0] );
		if ( ! AdminRegistry::is_privileged( $user ) ) {
			WP_CLI::error( "{$user->user_login} is not an administrator." );
		}
		$this->refuse_if_fixed();
		$this->c->get( AdminRegistry::class )->approve( $user->ID, 0 );
		WP_CLI::success( "Approved {$user->user_login} (ID {$user->ID})." );
	}

	/**
	 * Withdraws approval from an administrator account.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * @subcommand revoke-admin
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function revoke_admin( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$user = $this->find_user( $args[0] );
		$this->refuse_if_fixed();
		if ( ! $this->c->get( AdminRegistry::class )->revoke( $user->ID ) ) {
			WP_CLI::error( "{$user->user_login} was not approved." );
		}
		WP_CLI::success( "Withdrew approval for {$user->user_login}." );
	}

	/**
	 * Stops when the administrator list is fixed in wp-config.php.
	 */
	private function refuse_if_fixed(): void {
		if ( $this->c->get( AdminRegistry::class )->is_fixed() ) {
			WP_CLI::error( 'The administrator list is fixed by SENTINEL_SHIELD_ADMINS in wp-config.php. Edit it there.' );
		}
	}

	/**
	 * Resolves a user by ID, login or email.
	 *
	 * @param string $who Identifier.
	 */
	private function find_user( string $who ): \WP_User {
		$user = get_user_by( is_numeric( $who ) ? 'id' : ( is_email( $who ) ? 'email' : 'login' ), $who );
		if ( ! $user instanceof \WP_User ) {
			WP_CLI::error( "User not found: $who" );
		}
		return $user;
	}

	/**
	 * Prunes expired rules, old events, old offenses and used tokens.
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function prune( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );
		WP_CLI::success( 'Removed: ' . wp_json_encode( MaintenanceModule::run( $this->c ) ) );
	}

	/**
	 * Generates a one-time unlock link for an administrator.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * [--ip=<ip>]
	 * : IP to unlock in addition to the IP that opens the link.
	 *
	 * [--email]
	 * : Also email the link to the user.
	 *
	 * @subcommand unlock-link
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function unlock_link( array $args, array $assoc_args ): void {
		$user = get_user_by( is_numeric( $args[0] ) ? 'id' : ( is_email( $args[0] ) ? 'email' : 'login' ), $args[0] );
		if ( ! $user instanceof \WP_User || ! UnlockService::can_unlock( $user ) ) {
			WP_CLI::error( 'User not found or not an administrator.' );
		}
		$url = $this->c->get( UnlockService::class )->send_link( $user, (string) ( $assoc_args['ip'] ?? '' ), isset( $assoc_args['email'] ) );
		WP_CLI::log( $url );
	}

	/**
	 * Shows recent security events.
	 *
	 * ## OPTIONS
	 *
	 * [--event=<event>]
	 * : Filter by event type (blocked, would_block, lockout, would_lockout, unlock, ...).
	 *
	 * [--ip=<ip>]
	 * : Filter by IP.
	 *
	 * [--limit=<limit>]
	 * : Default 20.
	 *
	 * [--format=<format>]
	 * : table, csv, json, yaml. Default: table.
	 *
	 * @param array<int, string>    $args       Positional.
	 * @param array<string, string> $assoc_args Named.
	 */
	public function events( array $args, array $assoc_args ): void {
		unset( $args );
		[ $rows ] = $this->c->get( EventRepository::class )->query(
			array(
				'event'    => (string) ( $assoc_args['event'] ?? '' ),
				'ip'       => (string) ( $assoc_args['ip'] ?? '' ),
				'per_page' => (int) ( $assoc_args['limit'] ?? 20 ),
			)
		);
		WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'created_at', 'event', 'ip_text', 'module', 'reason', 'is_test', 'uri' ) );
	}

	/**
	 * Logs a configuration change made via CLI.
	 *
	 * @param string               $what    Description.
	 * @param array<string, mixed> $context Context.
	 */
	private function audit( string $what, array $context = array() ): void {
		$this->c->get( EventRepository::class )->log(
			'config_change',
			array(
				'module'  => 'cli',
				'reason'  => $what,
				'context' => $context,
			)
		);
	}
}
