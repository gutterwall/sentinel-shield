<?php
/**
 * Settings storage with network defaults and per-site overrides.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield;

use SentinelShield\Safety\SafetyGuard;

defined( 'ABSPATH' ) || exit;

/**
 * Merge order: built-in defaults -> network (or single-site) settings -> site overrides.
 * Only keys in OVERRIDABLE may be overridden per site; everything that affects
 * IP-level blocking is network-wide because the blocklist is shared.
 */
final class Settings {

	public const OPTION      = 'sentinel_shield_settings';
	public const SITE_OPTION = 'sentinel_shield_site_overrides';

	/**
	 * Keys a sub-site administrator may override.
	 */
	public const OVERRIDABLE = array( 'general.block_response', 'general.block_message', 'general.admin_bar' );

	/**
	 * Module slugs that exist in this build.
	 */
	public const MODULES = array( 'ip_gate', 'lockout', 'unlock' );

	/**
	 * Memoized merged settings.
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $merged = null;

	/**
	 * Built-in defaults. Fresh installs start in test mode so nothing is enforced
	 * until the admin has confirmed IP detection.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return array(
			'general' => array(
				'enabled'                  => true,
				'test_mode'                => true,
				'test_mode_hours'          => 0,
				'test_mode_until'          => 0,
				'test_mode_scope'          => 'all',
				'block_response'           => '403',
				'block_message'            => '',
				'event_retention_days'     => 30,
				'admin_bar'                => true,
				'delete_data_on_uninstall' => false,
			),
			'proxy'   => array(
				'mode'          => 'none',
				'header'        => 'X-Forwarded-For',
				'trusted_cidrs' => '',
				'server_ips'    => '',
			),
			'lockout' => array(
				'step1_minutes'      => 15,
				'step2_minutes'      => 60,
				'step3_minutes'      => 1440,
				'step4_minutes'      => 0,
				'repeat_window_days' => 7,
			),
			'unlock'  => array(
				'token_ttl_minutes'     => 30,
				'allow_hours'           => 24,
				'max_requests_per_hour' => 3,
			),
			'modules' => array(
				'ip_gate' => array(
					'enabled'   => true,
					'test_mode' => 'inherit',
				),
				'lockout' => array(
					'enabled'   => true,
					'test_mode' => 'inherit',
				),
				'unlock'  => array(
					'enabled'   => true,
					'test_mode' => 'inherit',
				),
			),
		);
	}

	/**
	 * Effective settings for the current site.
	 *
	 * @return array<string, mixed>
	 */
	public function all(): array {
		if ( null === $this->merged ) {
			$merged = $this->network_settings();
			if ( is_multisite() ) {
				$site = $this->site_overrides();
				foreach ( self::OVERRIDABLE as $path ) {
					if ( self::has_path( $site, $path ) ) {
						self::set_path( $merged, $path, self::get_path( $site, $path ) );
					}
				}
			}
			$this->merged = $merged;
		}
		return $this->merged;
	}

	/**
	 * Reads a value by dot path, e.g. "general.test_mode".
	 *
	 * @param string $path          Dot path.
	 * @param mixed  $default_value Fallback.
	 */
	public function get( string $path, mixed $default_value = null ): mixed {
		return self::get_path( $this->all(), $path, $default_value );
	}

	/**
	 * Network (or single-site) settings merged over defaults, without site overrides.
	 *
	 * @return array<string, mixed>
	 */
	public function network_settings(): array {
		$stored = get_site_option( self::OPTION, array() );
		return array_replace_recursive( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Raw per-site overrides.
	 *
	 * @return array<string, mixed>
	 */
	public function site_overrides(): array {
		if ( ! is_multisite() ) {
			return array();
		}
		$site = get_option( self::SITE_OPTION, array() );
		return is_array( $site ) ? $site : array();
	}

	/**
	 * Persists network settings.
	 *
	 * @param array<string, mixed> $settings Full, sanitized settings.
	 */
	public function save_network( array $settings ): void {
		update_site_option( self::OPTION, $settings );
		$this->merged = null;
		do_action( 'sentinel_shield_settings_saved', $settings );
	}

	/**
	 * Persists per-site overrides.
	 *
	 * @param array<string, mixed> $overrides Sanitized overrides.
	 */
	public function save_site_overrides( array $overrides ): void {
		update_option( self::SITE_OPTION, $overrides, false );
		$this->merged = null;
	}

	/**
	 * Drops the memoized merge (after external writes).
	 */
	public function refresh(): void {
		$this->merged = null;
	}

	/**
	 * Whether protection is on and the emergency constant is not set.
	 */
	public function is_enabled(): bool {
		return (bool) $this->get( 'general.enabled', true ) && ! SafetyGuard::emergency_disabled();
	}

	/**
	 * Whether a module is switched on.
	 *
	 * @param string $slug Module slug.
	 */
	public function is_module_enabled( string $slug ): bool {
		return (bool) $this->get( "modules.$slug.enabled", false );
	}

	/**
	 * Effective test mode for a module: module override ("on"/"off") or global.
	 *
	 * @param string $module Module slug, or '' for global.
	 */
	public function is_test_mode( string $module = '' ): bool {
		if ( '' !== $module ) {
			$override = (string) $this->get( "modules.$module.test_mode", 'inherit' );
			if ( 'on' === $override ) {
				return true;
			}
			if ( 'off' === $override ) {
				return false;
			}
		}
		return $this->global_test_mode();
	}

	/**
	 * Test mode for a chain of modules: the first explicit "on"/"off" override wins,
	 * otherwise the global setting applies. Used for lockouts triggered by another module.
	 *
	 * @param string ...$modules Module slugs, most specific first.
	 */
	public function is_test_mode_chain( string ...$modules ): bool {
		foreach ( $modules as $module ) {
			$override = (string) $this->get( "modules.$module.test_mode", 'inherit' );
			if ( 'on' === $override ) {
				return true;
			}
			if ( 'off' === $override ) {
				return false;
			}
		}
		return $this->global_test_mode();
	}

	/**
	 * Global test mode, honouring the optional auto-expiry.
	 */
	public function global_test_mode(): bool {
		if ( ! $this->get( 'general.test_mode', false ) ) {
			return false;
		}
		$until = (int) $this->get( 'general.test_mode_until', 0 );
		return 0 === $until || time() < $until;
	}

	/**
	 * Lockout steps in seconds; 0 means permanent and ends the sequence.
	 *
	 * @return list<int>
	 */
	public function lockout_durations(): array {
		$out = array();
		foreach ( array( 'step1_minutes', 'step2_minutes', 'step3_minutes', 'step4_minutes' ) as $key ) {
			$minutes = max( 0, (int) $this->get( "lockout.$key", 0 ) );
			$out[]   = $minutes * MINUTE_IN_SECONDS;
			if ( 0 === $minutes ) {
				break;
			}
		}
		return $out;
	}

	/**
	 * Window in seconds in which prior offenses escalate the next lockout.
	 */
	public function lockout_window(): int {
		return max( 1, (int) $this->get( 'lockout.repeat_window_days', 7 ) ) * DAY_IN_SECONDS;
	}

	/**
	 * Applies the test mode auto-expiry after general.test_mode or test_mode_hours change.
	 *
	 * @param array<string, mixed> $settings Settings to adjust.
	 * @return array<string, mixed>
	 */
	public static function apply_test_mode_expiry( array $settings ): array {
		$on    = ! empty( $settings['general']['test_mode'] );
		$hours = (int) ( $settings['general']['test_mode_hours'] ?? 0 );
		$settings['general']['test_mode_until'] = ( $on && $hours > 0 ) ? time() + ( $hours * HOUR_IN_SECONDS ) : 0;
		return $settings;
	}

	/**
	 * Dot-path read.
	 *
	 * @param array<string, mixed> $data          Data.
	 * @param string               $path          Dot path.
	 * @param mixed                $default_value Fallback.
	 */
	public static function get_path( array $data, string $path, mixed $default_value = null ): mixed {
		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $data ) || ! array_key_exists( $segment, $data ) ) {
				return $default_value;
			}
			$data = $data[ $segment ];
		}
		return $data;
	}

	/**
	 * Dot-path existence check.
	 *
	 * @param array<string, mixed> $data Data.
	 * @param string               $path Dot path.
	 */
	public static function has_path( array $data, string $path ): bool {
		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $data ) || ! array_key_exists( $segment, $data ) ) {
				return false;
			}
			$data = $data[ $segment ];
		}
		return true;
	}

	/**
	 * Dot-path write.
	 *
	 * @param array<string, mixed> $data  Data (by reference).
	 * @param string               $path  Dot path.
	 * @param mixed                $value Value.
	 */
	public static function set_path( array &$data, string $path, mixed $value ): void {
		$ref = &$data;
		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! isset( $ref[ $segment ] ) || ! is_array( $ref[ $segment ] ) ) {
				$ref[ $segment ] = array();
			}
			$ref = &$ref[ $segment ];
		}
		$ref = $value;
	}

	/**
	 * Dot-path delete.
	 *
	 * @param array<string, mixed> $data Data (by reference).
	 * @param string               $path Dot path.
	 */
	public static function unset_path( array &$data, string $path ): void {
		$segments = explode( '.', $path );
		$last     = array_pop( $segments );
		$ref      = &$data;
		foreach ( $segments as $segment ) {
			if ( ! isset( $ref[ $segment ] ) || ! is_array( $ref[ $segment ] ) ) {
				return;
			}
			$ref = &$ref[ $segment ];
		}
		unset( $ref[ $last ] );
	}
}
