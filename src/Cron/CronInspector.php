<?php
/**
 * Read-only view of scheduled WP-Cron events, their callbacks and recorded runs.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Cron;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress stores when an event runs next but nothing about past runs; those
 * come from CronRecorder. Callbacks are resolved with Reflection to the file
 * that defines them, so unexpected jobs (a common malware persistence trick)
 * can be traced to a plugin, theme, must-use plugin or uploaded file.
 */
final class CronInspector {

	/**
	 * Seconds past its scheduled time after which an event counts as overdue.
	 */
	public const OVERDUE_AFTER = 600;

	/**
	 * Scheduled events, soonest first, merged with their last recorded run.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function events(): array {
		$crons     = _get_cron_array();
		$schedules = wp_get_schedules();
		$runs      = CronRecorder::runs();
		$out       = array();
		foreach ( is_array( $crons ) ? $crons : array() as $timestamp => $hooks ) {
			foreach ( (array) $hooks as $hook => $events ) {
				foreach ( (array) $events as $sig => $event ) {
					$args     = (array) ( $event['args'] ?? array() );
					$schedule = $event['schedule'] ?? false;
					$key      = CronRecorder::key( (string) $hook, $args );
					$out[]    = array(
						'key'       => $key,
						'sig'       => (string) $sig,
						'hook'      => (string) $hook,
						'args'      => $args,
						'next_run'  => (int) $timestamp,
						'schedule'  => $schedule ? (string) $schedule : '',
						'interval'  => (int) ( $event['interval'] ?? 0 ),
						'recurs'    => $schedule ? (string) ( $schedules[ $schedule ]['display'] ?? $schedule ) : __( 'Once', 'sentinel-shield' ),
						'run'       => $runs[ $key ] ?? null,
						'callbacks' => self::callbacks( (string) $hook ),
					);
				}
			}
		}
		usort( $out, static fn( array $a, array $b ): int => $a['next_run'] <=> $b['next_run'] );
		return $out;
	}

	/**
	 * Recorded runs of events that are no longer scheduled (finished one-off jobs), newest first.
	 *
	 * @param list<array<string, mixed>> $scheduled Output of events().
	 * @return list<array<string, mixed>>
	 */
	public static function past_only( array $scheduled ): array {
		$keys = array_flip( array_column( $scheduled, 'key' ) );
		$out  = array_filter( CronRecorder::runs(), static fn( array $run, string $key ): bool => ! isset( $keys[ $key ] ), ARRAY_FILTER_USE_BOTH );
		usort( $out, static fn( array $a, array $b ): int => (float) $b['last_start'] <=> (float) $a['last_start'] );
		return $out;
	}

	/**
	 * Callbacks currently attached to a hook (excluding the recorder's own).
	 *
	 * @param string $hook Hook name.
	 * @return list<array{name:string, file:string, line:int, source:string, flag:string}>
	 */
	public static function callbacks( string $hook ): array {
		global $wp_filter;
		if ( ! isset( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof \WP_Hook ) {
			return array();
		}
		$out = array();
		foreach ( $wp_filter[ $hook ]->callbacks as $callbacks ) {
			foreach ( $callbacks as $callback ) {
				if ( CronRecorder::is_own( $callback['function'] ) ) {
					continue;
				}
				$out[] = self::describe( $callback['function'] );
			}
		}
		return $out;
	}

	/**
	 * Name, defining file and origin of one callback.
	 *
	 * @param mixed $callback Callable.
	 * @return array{name:string, file:string, line:int, source:string, flag:string}
	 */
	public static function describe( mixed $callback ): array {
		$name = 'unknown';
		$ref  = null;
		try {
			if ( $callback instanceof \Closure ) {
				$name = 'Closure';
				$ref  = new \ReflectionFunction( $callback );
			} elseif ( is_string( $callback ) && str_contains( $callback, '::' ) ) {
				$name = $callback;
				$ref  = new \ReflectionMethod( $callback );
			} elseif ( is_string( $callback ) ) {
				$name = $callback;
				$ref  = function_exists( $callback ) ? new \ReflectionFunction( $callback ) : null;
			} elseif ( is_array( $callback ) && 2 === count( $callback ) ) {
				$class = is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0];
				$name  = $class . ( is_object( $callback[0] ) ? '->' : '::' ) . (string) $callback[1];
				$ref   = new \ReflectionMethod( $class, (string) $callback[1] );
			} elseif ( is_object( $callback ) && method_exists( $callback, '__invoke' ) ) {
				$name = get_class( $callback ) . '->__invoke';
				$ref  = new \ReflectionMethod( $callback, '__invoke' );
			}
		} catch ( \ReflectionException $e ) {
			$ref = null;
		}
		$file              = $ref ? (string) $ref->getFileName() : '';
		[ $source, $flag ] = self::origin( $file );
		return array(
			'name'   => $name,
			'file'   => self::relative( $file ),
			'line'   => $ref ? (int) $ref->getStartLine() : 0,
			'source' => $source,
			'flag'   => $flag,
		);
	}

	/**
	 * Where a file lives: [label, flag] with flag '', 'notice' or 'warning'.
	 *
	 * @param string $file Absolute path.
	 * @return array{0:string, 1:string}
	 */
	public static function origin( string $file ): array {
		if ( '' === $file ) {
			return array( __( 'unknown (built-in or missing)', 'sentinel-shield' ), 'notice' );
		}
		$file    = wp_normalize_path( $file );
		$uploads = wp_get_upload_dir();
		$checks  = array(
			array( wp_normalize_path( (string) $uploads['basedir'] ), __( 'uploads folder', 'sentinel-shield' ), 'warning', false ),
			/* translators: %s: must-use plugin folder name. */
			array( wp_normalize_path( WPMU_PLUGIN_DIR ), __( 'must-use plugin: %s', 'sentinel-shield' ), 'notice', true ),
			/* translators: %s: plugin folder name. */
			array( wp_normalize_path( WP_PLUGIN_DIR ), __( 'plugin: %s', 'sentinel-shield' ), '', true ),
			/* translators: %s: theme folder name. */
			array( wp_normalize_path( get_theme_root() ), __( 'theme: %s', 'sentinel-shield' ), '', true ),
			array( wp_normalize_path( ABSPATH . WPINC ), __( 'WordPress core', 'sentinel-shield' ), '', false ),
			array( wp_normalize_path( ABSPATH . 'wp-admin' ), __( 'WordPress core', 'sentinel-shield' ), '', false ),
		);
		if ( str_contains( $file, "eval()'d code" ) ) {
			return array( __( 'eval()\'d code', 'sentinel-shield' ), 'warning' );
		}
		// PHP reports real paths, so a symlinked plugin folder would otherwise look foreign.
		foreach ( self::symlinked_plugins() as $target => $slug ) {
			if ( str_starts_with( $file, $target . '/' ) ) {
				/* translators: %s: plugin folder name. */
				return array( sprintf( __( 'plugin: %s', 'sentinel-shield' ), $slug ), '' );
			}
		}
		foreach ( $checks as [ $dir, $label, $flag, $named ] ) {
			if ( '' !== $dir && str_starts_with( $file, trailingslashit( $dir ) ) ) {
				$first = explode( '/', substr( $file, strlen( trailingslashit( $dir ) ) ) )[0];
				return array( $named ? sprintf( $label, $first ) : $label, $flag );
			}
		}
		return array( __( 'other location', 'sentinel-shield' ), 'notice' );
	}

	/**
	 * Real paths of symlinked plugin folders, mapped to their folder name.
	 *
	 * @return array<string, string>
	 */
	private static function symlinked_plugins(): array {
		static $map = null;
		if ( null === $map ) {
			$map = array();
			foreach ( (array) glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR ) as $dir ) {
				$real = is_link( (string) $dir ) ? realpath( (string) $dir ) : false;
				if ( false !== $real ) {
					$map[ wp_normalize_path( $real ) ] = basename( (string) $dir );
				}
			}
		}
		return $map;
	}

	/**
	 * WP-CLI command that runs every event of a hook now.
	 *
	 * @param string $hook Hook name.
	 */
	public static function command( string $hook ): string {
		return 'wp cron event run ' . ( preg_match( '/^[A-Za-z0-9_\-.\/:]+$/', $hook ) ? $hook : escapeshellarg( $hook ) );
	}

	/**
	 * Path relative to the WordPress root when inside it.
	 *
	 * @param string $file Absolute path.
	 */
	public static function relative( string $file ): string {
		$file = wp_normalize_path( $file );
		$root = wp_normalize_path( ABSPATH );
		return str_starts_with( $file, $root ) ? substr( $file, strlen( $root ) ) : $file;
	}

	/**
	 * Overall WP-Cron health facts.
	 *
	 * @param list<array<string, mixed>> $events Output of events().
	 * @return array{disabled:bool, alternate:bool, last_request:int, overdue:int, total:int}
	 */
	public static function health( array $events ): array {
		$now     = time();
		$overdue = count( array_filter( $events, static fn( array $e ): bool => $e['next_run'] < $now - self::OVERDUE_AFTER ) );
		return array(
			'disabled'     => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'alternate'    => defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON,
			'last_request' => CronRecorder::last_request(),
			'overdue'      => $overdue,
			'total'        => count( $events ),
		);
	}
}
