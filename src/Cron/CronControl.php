<?php
/**
 * Admin actions on scheduled WP-Cron events: run now, pause, resume, reschedule, delete.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Cron;

defined( 'ABSPATH' ) || exit;

/**
 * Every action targets an event that already exists (looked up by timestamp,
 * hook and WordPress's own argument signature), so the UI can never create
 * arbitrary hooks. Pausing removes the event and remembers it; while paused,
 * attempts by its plugin to schedule it again are refused, because many plugins
 * re-add missing events on every page load.
 */
final class CronControl {

	public const PAUSED_OPTION = 'sentinel_shield_cron_paused';

	/**
	 * Refuses to schedule paused events. Always registered, so a pause holds
	 * even if the monitor module is switched off.
	 */
	public static function register_guard(): void {
		add_filter( 'pre_schedule_event', array( self::class, 'block_paused' ), 10, 2 );
	}

	/**
	 * Filter callback for pre_schedule_event.
	 *
	 * @param mixed     $pre   Short-circuit value.
	 * @param \stdClass $event Event being scheduled.
	 * @return mixed False to refuse, otherwise $pre unchanged.
	 */
	public static function block_paused( mixed $pre, \stdClass $event ): mixed {
		if ( null !== $pre ) {
			return $pre;
		}
		$paused = self::paused();
		return isset( $paused[ self::paused_key( (string) $event->hook, (array) $event->args ) ] ) ? false : $pre;
	}

	/**
	 * Paused events keyed by hook and argument signature.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function paused(): array {
		$paused = get_option( self::PAUSED_OPTION, array() );
		return is_array( $paused ) ? $paused : array();
	}

	/**
	 * A scheduled event, or null if it no longer exists.
	 *
	 * @param int    $timestamp Scheduled time.
	 * @param string $hook      Hook name.
	 * @param string $sig       WordPress argument signature (md5 of serialized args).
	 * @return array{timestamp:int, hook:string, sig:string, args:array<mixed>, schedule:string, interval:int}|null
	 */
	public static function find( int $timestamp, string $hook, string $sig ): ?array {
		$crons = _get_cron_array();
		$event = is_array( $crons ) ? ( $crons[ $timestamp ][ $hook ][ $sig ] ?? null ) : null;
		if ( ! is_array( $event ) ) {
			return null;
		}
		return array(
			'timestamp' => $timestamp,
			'hook'      => $hook,
			'sig'       => $sig,
			'args'      => (array) ( $event['args'] ?? array() ),
			'schedule'  => (string) ( $event['schedule'] ?? '' ),
			'interval'  => (int) ( $event['interval'] ?? 0 ),
		);
	}

	/**
	 * Moves the event to "now" and asks WordPress to start a cron run.
	 *
	 * @param array<string, mixed> $event Event from find().
	 * @return true|\WP_Error
	 */
	public static function run_now( array $event ): bool|\WP_Error {
		$moved = self::move( $event, time() - 1, (string) $event['schedule'] );
		if ( is_wp_error( $moved ) ) {
			return $moved;
		}
		delete_transient( 'doing_cron' );
		spawn_cron();
		return true;
	}

	/**
	 * Unschedules the event and remembers it so it can be resumed.
	 *
	 * @param array<string, mixed> $event   Event from find().
	 * @param int                  $user_id Acting user.
	 * @return true|\WP_Error
	 */
	public static function pause( array $event, int $user_id ): bool|\WP_Error {
		$removed = wp_unschedule_event( (int) $event['timestamp'], (string) $event['hook'], (array) $event['args'], true );
		if ( is_wp_error( $removed ) ) {
			return $removed;
		}
		$paused = self::paused();
		$paused[ self::paused_key( (string) $event['hook'], (array) $event['args'] ) ] = array(
			'hook'      => (string) $event['hook'],
			'args'      => (array) $event['args'],
			'schedule'  => (string) $event['schedule'],
			'timestamp' => (int) $event['timestamp'],
			'paused_at' => time(),
			'user_id'   => $user_id,
		);
		update_option( self::PAUSED_OPTION, $paused, true );
		return true;
	}

	/**
	 * Schedules a paused event again: at its old time if still ahead, otherwise in a minute.
	 *
	 * @param string $key Paused key.
	 * @return true|\WP_Error
	 */
	public static function resume( string $key ): bool|\WP_Error {
		$paused = self::paused();
		if ( ! isset( $paused[ $key ] ) ) {
			return new \WP_Error( 'sentinel_shield_cron_missing', __( 'That task is not paused.', 'sentinel-shield' ) );
		}
		$event = $paused[ $key ];
		unset( $paused[ $key ] );
		update_option( self::PAUSED_OPTION, $paused, true );
		$when      = max( (int) $event['timestamp'], time() + MINUTE_IN_SECONDS );
		$schedules = wp_get_schedules();
		if ( '' !== $event['schedule'] && isset( $schedules[ $event['schedule'] ] ) ) {
			return self::as_result( wp_schedule_event( $when, (string) $event['schedule'], (string) $event['hook'], (array) $event['args'], true ) );
		}
		return self::as_result( wp_schedule_single_event( $when, (string) $event['hook'], (array) $event['args'], true ) );
	}

	/**
	 * Forgets a paused event without scheduling it again.
	 *
	 * @param string $key Paused key.
	 */
	public static function forget( string $key ): bool {
		$paused = self::paused();
		if ( ! isset( $paused[ $key ] ) ) {
			return false;
		}
		unset( $paused[ $key ] );
		update_option( self::PAUSED_OPTION, $paused, true );
		return true;
	}

	/**
	 * Removes one scheduled event.
	 *
	 * @param array<string, mixed> $event Event from find().
	 * @return true|\WP_Error
	 */
	public static function delete( array $event ): bool|\WP_Error {
		return self::as_result( wp_unschedule_event( (int) $event['timestamp'], (string) $event['hook'], (array) $event['args'], true ) );
	}

	/**
	 * Changes how often an event repeats and/or when it next runs.
	 *
	 * @param array<string, mixed> $event    Event from find().
	 * @param string               $schedule Schedule name, or '' for a one-off run.
	 * @param int                  $next     Next run (Unix time).
	 * @return true|\WP_Error
	 */
	public static function reschedule( array $event, string $schedule, int $next ): bool|\WP_Error {
		if ( '' !== $schedule && ! isset( wp_get_schedules()[ $schedule ] ) ) {
			return new \WP_Error( 'sentinel_shield_cron_schedule', __( 'Unknown schedule.', 'sentinel-shield' ) );
		}
		if ( $next < time() - DAY_IN_SECONDS || $next > time() + 10 * YEAR_IN_SECONDS ) {
			return new \WP_Error( 'sentinel_shield_cron_time', __( 'Choose a next run time between yesterday and ten years from now.', 'sentinel-shield' ) );
		}
		return self::move( $event, $next, $schedule );
	}

	/**
	 * Key used for paused events (hook plus WordPress's argument signature).
	 *
	 * @param string       $hook Hook name.
	 * @param array<mixed> $args Arguments.
	 */
	public static function paused_key( string $hook, array $args ): string {
		return $hook . '|' . md5( serialize( $args ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- WordPress's own event signature.
	}

	/**
	 * Unschedules an event and schedules it again at a new time/schedule; restores it on failure.
	 *
	 * @param array<string, mixed> $event    Event from find().
	 * @param int                  $when     New time.
	 * @param string               $schedule Schedule name or '' for once.
	 * @return true|\WP_Error
	 */
	private static function move( array $event, int $when, string $schedule ): bool|\WP_Error {
		$hook    = (string) $event['hook'];
		$args    = (array) $event['args'];
		$removed = wp_unschedule_event( (int) $event['timestamp'], $hook, $args, true );
		if ( is_wp_error( $removed ) ) {
			return $removed;
		}
		$added = '' === $schedule
			? wp_schedule_single_event( $when, $hook, $args, true )
			: wp_schedule_event( $when, $schedule, $hook, $args, true );
		if ( is_wp_error( $added ) ) {
			// Put the original back so nothing is lost.
			if ( '' === (string) $event['schedule'] ) {
				wp_schedule_single_event( (int) $event['timestamp'], $hook, $args );
			} else {
				wp_schedule_event( (int) $event['timestamp'], (string) $event['schedule'], $hook, $args );
			}
			return $added;
		}
		return true;
	}

	/**
	 * Normalizes core return values.
	 *
	 * @param bool|\WP_Error $result Result.
	 * @return true|\WP_Error
	 */
	private static function as_result( bool|\WP_Error $result ): bool|\WP_Error {
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return $result ? true : new \WP_Error( 'sentinel_shield_cron_failed', __( 'WordPress refused the change.', 'sentinel-shield' ) );
	}
}
