<?php
/**
 * Scheduled tasks (WP-Cron) monitor.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Cron\CronControl;
use SentinelShield\Cron\CronInspector;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Lists every scheduled event with its next run, last recorded run, the code it
 * calls and the WP-CLI command that runs it. Read-only.
 */
final class CronPage {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Renders the page.
	 */
	public function render(): void {
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		// Cron is per site; in the network admin show the main site.
		$switched = is_multisite() && get_current_blog_id() !== get_main_site_id();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		$events = CronInspector::events();
		$paused = CronControl::paused();
		$past   = CronInspector::past_only( $events );
		$health = CronInspector::health( $events );
		$site   = home_url( '/' );
		if ( $switched ) {
			restore_current_blog();
		}

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Scheduled Tasks (WP-Cron)', 'sentinel-shield' ) . '</h1>';
		if ( is_multisite() ) {
			/* translators: %s: site URL. */
			echo '<p>' . esc_html( sprintf( __( 'Showing the main site (%s). Each site in a network has its own scheduled tasks.', 'sentinel-shield' ), $site ) ) . '</p>';
		}
		if ( ! $this->c->get( Settings::class )->is_module_enabled( 'cron_monitor' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The "Scheduled task monitor" module is off on Settings → Modules, so last-run results are not being recorded.', 'sentinel-shield' ) . '</p></div>';
		}
		$this->health_card( $health, $site );
		if ( $paused ) {
			$this->paused_table( $paused );
		}
		$this->events_table( $events );
		if ( $past ) {
			$this->past_table( array_slice( $past, 0, 50 ) );
		}
		echo '</div>';
	}

	/**
	 * Summary of whether WP-Cron is running.
	 *
	 * @param array{disabled:bool, alternate:bool, last_request:int, overdue:int, total:int} $health Health facts.
	 * @param string                                                                         $site   Site URL.
	 */
	private function health_card( array $health, string $site ): void {
		echo '<div class="ss-grid ss-grid-4">';
		$mode = $health['disabled']
			? array( __( 'Built-in trigger off', 'sentinel-shield' ), 'warn', __( 'DISABLE_WP_CRON is set: a system cron job must call wp-cron.php.', 'sentinel-shield' ) )
			: ( $health['alternate']
				? array( __( 'Alternate mode', 'sentinel-shield' ), 'info', __( 'ALTERNATE_WP_CRON is set: runs via redirects on page views.', 'sentinel-shield' ) )
				: array( __( 'Visitor-triggered', 'sentinel-shield' ), 'ok', __( 'Runs when the site gets page views. Quiet sites may run tasks late.', 'sentinel-shield' ) ) );
		$this->stat( __( 'WP-Cron mode', 'sentinel-shield' ), View::pill( $mode[0], $mode[1] ), $mode[2] );

		$last = $health['last_request'];
		$this->stat(
			__( 'wp-cron.php last ran', 'sentinel-shield' ),
			esc_html( $last ? self::ago( $last ) : __( 'Not seen yet', 'sentinel-shield' ) ),
			$last ? wp_date( 'Y-m-d H:i:s', $last ) : __( 'Recorded from now on.', 'sentinel-shield' )
		);
		$this->stat(
			__( 'Overdue tasks', 'sentinel-shield' ),
			$health['overdue'] ? View::pill( (string) $health['overdue'], 'bad' ) : View::pill( '0', 'ok' ),
			$health['overdue'] ? __( 'More than 10 minutes late. If this persists, WP-Cron is not being triggered.', 'sentinel-shield' ) : __( 'Everything is on time.', 'sentinel-shield' )
		);
		$this->stat( __( 'Scheduled tasks', 'sentinel-shield' ), esc_html( number_format_i18n( $health['total'] ) ), __( 'Recurring and one-off events.', 'sentinel-shield' ) );
		echo '</div>';

		if ( $health['disabled'] || $health['overdue'] ) {
			echo '<div class="ss-card"><h2>' . esc_html__( 'Running WP-Cron from the server', 'sentinel-shield' ) . '</h2>';
			echo '<p>' . esc_html__( 'A reliable setup is to add DISABLE_WP_CRON to wp-config.php and let the server run due tasks every 5 minutes with one of these crontab lines:', 'sentinel-shield' ) . '</p>';
			$this->command( '*/5 * * * * cd ' . untrailingslashit( ABSPATH ) . ' && wp cron event run --due-now >/dev/null 2>&1' );
			$this->command( '*/5 * * * * curl -s ' . $site . 'wp-cron.php?doing_wp_cron >/dev/null 2>&1' );
			echo '</div>';
		}
	}

	/**
	 * All scheduled events.
	 *
	 * @param list<array<string, mixed>> $events Events.
	 */
	private function events_table( array $events ): void {
		echo '<h2>' . esc_html__( 'Scheduled', 'sentinel-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'WordPress itself only stores the next run. Last-run results are recorded by Sentinel Shield each time a task runs, so tasks show "Not seen yet" until their first run after installation. A task whose code lives in the uploads folder or in eval()\'d code is highlighted: legitimate plugins do not do that.', 'sentinel-shield' ) . '</p>';
		echo '<div class="ss-scroll"><table class="widefat striped ss-cron"><thead><tr>';
		foreach ( array( __( 'Task (hook) and code it runs', 'sentinel-shield' ), __( 'Repeats', 'sentinel-shield' ), __( 'Next run', 'sentinel-shield' ), __( 'Last run', 'sentinel-shield' ), __( 'Command line', 'sentinel-shield' ), __( 'Control', 'sentinel-shield' ) ) as $heading ) {
			echo '<th>' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( ! $events ) {
			echo '<tr><td colspan="6">' . esc_html__( 'No scheduled tasks.', 'sentinel-shield' ) . '</td></tr>';
		}
		foreach ( $events as $event ) {
			$run = is_array( $event['run'] ) ? $event['run'] : null;
			echo '<tr><td><code class="ss-hook">' . esc_html( $event['hook'] ) . '</code>';
			if ( $event['args'] ) {
				echo '<br><span class="description">' . esc_html__( 'Arguments:', 'sentinel-shield' ) . ' <code>' . esc_html( mb_strimwidth( (string) wp_json_encode( $event['args'] ), 0, 160, '…' ) ) . '</code></span>';
			}
			$this->callbacks( $event['callbacks'], $run );
			echo '</td><td>' . esc_html( $event['recurs'] ) . '</td>';

			$next = (int) $event['next_run'];
			echo '<td>' . esc_html( wp_date( 'Y-m-d H:i', $next ) ) . '<br>';
			if ( $next < time() - CronInspector::OVERDUE_AFTER ) {
				/* translators: %s: time span. */
				echo View::pill( sprintf( __( 'Overdue by %s', 'sentinel-shield' ), human_time_diff( $next ) ), 'bad' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			} else {
				echo '<span class="description">' . esc_html( $next <= time() ? __( 'Due now', 'sentinel-shield' ) : self::in( $next ) ) . '</span>';
			}
			echo '</td><td>';
			$this->last_run( $run );
			echo '</td><td>';
			$this->command( CronInspector::command( $event['hook'] ) );
			if ( $event['args'] ) {
				echo '<span class="description">' . esc_html__( 'Runs every scheduled event of this hook.', 'sentinel-shield' ) . '</span>';
			}
			echo '</td><td class="ss-controls">';
			$this->controls( $event );
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * Buttons and the reschedule form for one event.
	 *
	 * @param array<string, mixed> $event Event.
	 */
	private function controls( array $event ): void {
		$core    = self::is_core( $event['callbacks'] );
		$caution = $core ? ' ' . __( 'This is a WordPress core task (for example update or security checks); stopping it can leave the site unpatched.', 'sentinel-shield' ) : '';
		$this->button( $event, 'run', __( 'Run now', 'sentinel-shield' ), 'primary', '' );
		/* translators: %s: hook name. */
		$this->button( $event, 'pause', __( 'Pause', 'sentinel-shield' ), 'secondary', sprintf( __( 'Pause %s? It will not run, and its plugin cannot re-add it, until you resume it.', 'sentinel-shield' ), $event['hook'] ) . $caution );
		/* translators: %s: hook name. */
		$this->button( $event, 'delete', __( 'Delete', 'sentinel-shield' ), 'link-delete', sprintf( __( 'Delete %s? Its plugin may schedule it again on the next page load.', 'sentinel-shield' ), $event['hook'] ) . $caution );

		echo '<details class="ss-resched"><summary>' . esc_html__( 'Change schedule', 'sentinel-shield' ) . '</summary>';
		View::form_open( 'cron_control' );
		$this->identity( $event );
		echo '<input type="hidden" name="op" value="reschedule">';
		$id = 'ss-sched-' . md5( $event['key'] . $event['next_run'] );
		echo '<p><label for="' . esc_attr( $id ) . '">' . esc_html__( 'Repeats', 'sentinel-shield' ) . '</label><br><select id="' . esc_attr( $id ) . '" name="schedule">';
		echo '<option value="once" ' . selected( '', $event['schedule'], false ) . '>' . esc_html__( 'Once (no repeat)', 'sentinel-shield' ) . '</option>';
		$schedules = wp_get_schedules();
		uasort( $schedules, static fn( array $a, array $b ): int => (int) $a['interval'] <=> (int) $b['interval'] );
		foreach ( $schedules as $name => $schedule ) {
			echo '<option value="' . esc_attr( (string) $name ) . '" ' . selected( (string) $name, $event['schedule'], false ) . '>' . esc_html( (string) $schedule['display'] ) . '</option>';
		}
		echo '</select></p><p><label for="' . esc_attr( $id ) . '-t">' . esc_html__( 'Next run (site time)', 'sentinel-shield' ) . '</label><br>';
		echo '<input type="datetime-local" id="' . esc_attr( $id ) . '-t" name="next_run" value="' . esc_attr( wp_date( 'Y-m-d\TH:i', (int) $event['next_run'] ) ) . '"></p>';
		submit_button( __( 'Save schedule', 'sentinel-shield' ), 'small', 'submit', false );
		echo '</form></details>';
	}

	/**
	 * One action button in its own form.
	 *
	 * @param array<string, mixed> $event   Event.
	 * @param string               $op      Operation.
	 * @param string               $label   Button label.
	 * @param string               $style   primary|secondary|link-delete.
	 * @param string               $confirm Confirmation prompt, '' for none.
	 */
	private function button( array $event, string $op, string $label, string $style, string $confirm ): void {
		View::form_open( 'cron_control' );
		$this->identity( $event );
		echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		$class = 'link-delete' === $style ? 'button button-small button-link-delete' : 'button button-small' . ( 'primary' === $style ? ' button-primary' : '' );
		echo '<button type="submit" class="' . esc_attr( $class ) . '"' . ( '' !== $confirm ? ' data-sentinel-confirm="' . esc_attr( $confirm ) . '"' : '' ) . '>' . esc_html( $label ) . '</button>';
		echo '</form>';
	}

	/**
	 * Hidden fields that pin a form to one exact scheduled event.
	 *
	 * @param array<string, mixed> $event Event.
	 */
	private function identity( array $event ): void {
		echo '<input type="hidden" name="timestamp" value="' . esc_attr( (string) $event['next_run'] ) . '">';
		echo '<input type="hidden" name="hook" value="' . esc_attr( (string) $event['hook'] ) . '">';
		echo '<input type="hidden" name="sig" value="' . esc_attr( (string) $event['sig'] ) . '">';
	}

	/**
	 * Whether every callback of a task is WordPress core code.
	 *
	 * @param list<array<string, mixed>> $callbacks Callbacks.
	 */
	private static function is_core( array $callbacks ): bool {
		if ( ! $callbacks ) {
			return false;
		}
		foreach ( $callbacks as $cb ) {
			if ( __( 'WordPress core', 'sentinel-shield' ) !== $cb['source'] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Paused tasks with Resume and Delete.
	 *
	 * @param array<string, array<string, mixed>> $paused Paused tasks keyed by pause key.
	 */
	private function paused_table( array $paused ): void {
		echo '<h2>' . esc_html__( 'Paused', 'sentinel-shield' ) . '</h2>';
		echo '<div class="ss-scroll"><table class="widefat striped ss-cron"><thead><tr><th>' . esc_html__( 'Task (hook)', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Repeats', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Paused', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Control', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		$schedules = wp_get_schedules();
		foreach ( $paused as $key => $task ) {
			$user = get_userdata( (int) $task['user_id'] );
			echo '<tr><td><code class="ss-hook">' . esc_html( (string) $task['hook'] ) . '</code>';
			if ( $task['args'] ) {
				echo '<br><span class="description">' . esc_html__( 'Arguments:', 'sentinel-shield' ) . ' <code>' . esc_html( mb_strimwidth( (string) wp_json_encode( $task['args'] ), 0, 160, '…' ) ) . '</code></span>';
			}
			echo '</td><td>' . esc_html( '' === $task['schedule'] ? __( 'Once', 'sentinel-shield' ) : (string) ( $schedules[ $task['schedule'] ]['display'] ?? $task['schedule'] ) ) . '</td>';
			echo '<td>' . esc_html( self::ago( (int) $task['paused_at'] ) . ( $user ? ' · ' . $user->user_login : '' ) ) . '</td><td class="ss-controls">';
			foreach ( array(
				'resume' => array( __( 'Resume', 'sentinel-shield' ), 'button button-small button-primary', '' ),
				/* translators: %s: hook name. */
				'forget' => array( __( 'Delete', 'sentinel-shield' ), 'button button-small button-link-delete', sprintf( __( 'Delete paused task %s for good? Its plugin may schedule it again.', 'sentinel-shield' ), (string) $task['hook'] ) ),
			) as $op => [ $label, $class, $confirm ] ) {
				View::form_open( 'cron_control' );
				echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '"><input type="hidden" name="key" value="' . esc_attr( (string) $key ) . '">';
				echo '<button type="submit" class="' . esc_attr( $class ) . '"' . ( '' !== $confirm ? ' data-sentinel-confirm="' . esc_attr( $confirm ) . '"' : '' ) . '>' . esc_html( $label ) . '</button></form>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * Recently run tasks that are no longer scheduled.
	 *
	 * @param list<array<string, mixed>> $runs Runs.
	 */
	private function past_table( array $runs ): void {
		echo '<h2>' . esc_html__( 'Recently run, no longer scheduled', 'sentinel-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'One-off tasks that have finished, and recurring tasks whose plugin removed them.', 'sentinel-shield' ) . '</p>';
		echo '<div class="ss-scroll"><table class="widefat striped ss-cron"><thead><tr><th>' . esc_html__( 'Task (hook) and code it ran', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last run', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		foreach ( $runs as $run ) {
			echo '<tr><td><code class="ss-hook">' . esc_html( (string) $run['hook'] ) . '</code>';
			if ( ! empty( $run['args'] ) && '[]' !== $run['args'] ) {
				echo '<br><span class="description">' . esc_html__( 'Arguments:', 'sentinel-shield' ) . ' <code>' . esc_html( (string) $run['args'] ) . '</code></span>';
			}
			$this->callbacks( array(), $run );
			echo '</td><td>';
			$this->last_run( $run );
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * Callbacks attached now, or as recorded at the last run.
	 *
	 * @param list<array<string, mixed>> $live Callbacks resolved on this request.
	 * @param array<string, mixed>|null  $run  Last run record.
	 */
	private function callbacks( array $live, ?array $run ): void {
		echo '<ul class="ss-callbacks">';
		$recorded = $run && is_array( $run['callbacks'] ?? null ) ? array_filter( $run['callbacks'], 'is_array' ) : array();
		if ( $live || $recorded ) {
			foreach ( $live ? $live : $recorded as $cb ) {
				echo '<li><code>' . esc_html( (string) $cb['name'] ) . '</code> ';
				$state = 'warning' === $cb['flag'] ? 'bad' : ( 'notice' === $cb['flag'] ? 'warn' : 'info' );
				echo View::pill( (string) $cb['source'], $state ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
				if ( '' !== $cb['file'] ) {
					echo '<br><span class="description">' . esc_html( $cb['file'] . ':' . $cb['line'] ) . '</span>';
				}
				echo '</li>';
			}
			if ( ! $live ) {
				echo '<li class="description">' . esc_html__( '(as recorded at the last run)', 'sentinel-shield' ) . '</li>';
			}
		} else {
			echo '<li>' . View::pill( __( 'No code attached: nothing runs', 'sentinel-shield' ), 'warn' ) . ' <span class="description">' . esc_html__( 'Usually left behind by a removed plugin.', 'sentinel-shield' ) . '</span></li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</ul>';
	}

	/**
	 * Last-run cell.
	 *
	 * @param array<string, mixed>|null $run Last run record.
	 */
	private function last_run( ?array $run ): void {
		if ( null === $run ) {
			echo View::pill( __( 'Not seen yet', 'sentinel-shield' ), 'info' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			return;
		}
		$start = (int) $run['last_start'];
		$ok    = 'ok' === $run['status'];
		echo View::pill( $ok ? __( 'Completed', 'sentinel-shield' ) : __( 'Failed', 'sentinel-shield' ), $ok ? 'ok' : 'bad' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		echo ' ' . esc_html( self::ago( $start ) ) . '<br><span class="description">' . esc_html( wp_date( 'Y-m-d H:i:s', $start ) );
		/* translators: 1: seconds, 2: number of runs, 3: cron or cli. */
		echo ' · ' . esc_html( sprintf( _n( '%1$ss · %2$d run recorded · via %3$s', '%1$ss · %2$d runs recorded · via %3$s', (int) $run['count'], 'sentinel-shield' ), number_format_i18n( (float) $run['duration'], 2 ), (int) $run['count'], 'cli' === $run['context'] ? 'WP-CLI' : 'wp-cron' ) ) . '</span>';
		if ( ! $ok ) {
			echo '<br><span class="ss-error">' . esc_html( (string) $run['error'] ) . '</span>';
			if ( (int) $run['failures'] > 1 ) {
				/* translators: %d: count. */
				echo '<br><span class="ss-error">' . esc_html( sprintf( __( 'Failed %d times in a row.', 'sentinel-shield' ), (int) $run['failures'] ) ) . '</span>';
			}
			if ( ! empty( $run['last_ok'] ) ) {
				/* translators: %s: time ago. */
				echo '<br><span class="description">' . esc_html( sprintf( __( 'Last success: %s', 'sentinel-shield' ), self::ago( (int) $run['last_ok'] ) ) ) . '</span>';
			}
		}
	}

	/**
	 * A copyable command.
	 *
	 * @param string $command Command line.
	 */
	private function command( string $command ): void {
		echo '<div class="ss-cmd"><code>' . esc_html( $command ) . '</code> <button type="button" class="button button-small" data-ss-copy="' . esc_attr( $command ) . '">' . esc_html__( 'Copy', 'sentinel-shield' ) . '</button></div>';
	}

	/**
	 * Stat tile.
	 *
	 * @param string $label Label.
	 * @param string $value Escaped HTML value.
	 * @param string $sub   Sub text.
	 */
	private function stat( string $label, string $value, string $sub ): void {
		echo '<div class="ss-card"><div class="ss-stat-label">' . esc_html( $label ) . '</div><div class="ss-stat-value">' . $value . '</div><div class="ss-stat-sub">' . esc_html( $sub ) . '</div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Callers pass escaped HTML.
	}

	/**
	 * "5 minutes ago".
	 *
	 * @param int $time Unix time.
	 */
	private static function ago( int $time ): string {
		/* translators: %s: time span. */
		return sprintf( __( '%s ago', 'sentinel-shield' ), human_time_diff( $time ) );
	}

	/**
	 * "in 5 minutes".
	 *
	 * @param int $time Unix time.
	 */
	private static function in( int $time ): string {
		/* translators: %s: time span. */
		return sprintf( __( 'in %s', 'sentinel-shield' ), human_time_diff( $time ) );
	}
}
