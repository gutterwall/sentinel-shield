<?php
/**
 * Records when each WP-Cron event last ran, how long it took and whether it finished.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Cron;

defined( 'ABSPATH' ) || exit;

/**
 * Only active in cron requests (wp-cron.php or a system cron) and WP-CLI. Every
 * scheduled hook gets a first and a last callback that time the run; anything
 * still running at shutdown is recorded as failed (fatal error, timeout or exit).
 * Results are written once per request to a non-autoloaded option of the site.
 */
final class CronRecorder {

	public const OPTION      = 'sentinel_shield_cron_runs';
	public const MAX_ENTRIES = 300;

	/**
	 * The recorder for this request, if recording.
	 *
	 * @var CronRecorder|null
	 */
	private static ?CronRecorder $active = null;

	/**
	 * Runs in progress: [key, hook, start, callbacks, args JSON].
	 *
	 * @var list<array{0:string, 1:string, 2:float, 3:list<array<string, mixed>>, 4:string}>
	 */
	private array $stack = array();

	/**
	 * Finished runs this request, keyed by event key.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private array $results = array();

	/**
	 * Constructor.
	 *
	 * @param string $context "cron" or "cli".
	 */
	private function __construct( private string $context ) {}

	/**
	 * Starts recording when this request can run cron events. Hooked to wp_loaded.
	 */
	public static function maybe_start(): void {
		$cli = defined( 'WP_CLI' ) && WP_CLI;
		if ( null !== self::$active || ( ! wp_doing_cron() && ! $cli ) ) {
			return;
		}
		$recorder     = new self( $cli ? 'cli' : 'cron' );
		self::$active = $recorder;
		$crons        = _get_cron_array();
		$hooks        = array();
		foreach ( is_array( $crons ) ? $crons : array() as $events ) {
			foreach ( array_keys( (array) $events ) as $hook ) {
				$hooks[ (string) $hook ] = true;
			}
		}
		foreach ( array_keys( $hooks ) as $hook ) {
			add_action( $hook, array( $recorder, 'before' ), PHP_INT_MIN, 99 );
			add_action( $hook, array( $recorder, 'after' ), PHP_INT_MAX, 99 );
		}
		register_shutdown_function( array( $recorder, 'shutdown' ) );
	}

	/**
	 * Identifies an event the way the run log stores it.
	 *
	 * @param string       $hook Hook name.
	 * @param array<mixed> $args Event arguments.
	 */
	public static function key( string $hook, array $args ): string {
		return $hook . '|' . md5( serialize( array_values( $args ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Same scheme WordPress uses for cron event keys.
	}

	/**
	 * Whether a callback is one of the recorder's own.
	 *
	 * @param mixed $callback Callable.
	 */
	public static function is_own( mixed $callback ): bool {
		return is_array( $callback ) && isset( $callback[0] ) && $callback[0] instanceof self;
	}

	/**
	 * Recorded runs keyed by event key.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function runs(): array {
		$data = get_option( self::OPTION, array() );
		return is_array( $data ) && is_array( $data['runs'] ?? null ) ? $data['runs'] : array();
	}

	/**
	 * When wp-cron.php last ran on this site (0 = not since recording started).
	 */
	public static function last_request(): int {
		$data = get_option( self::OPTION, array() );
		return is_array( $data ) ? (int) ( $data['last_request'] ?? 0 ) : 0;
	}

	/**
	 * First callback on a scheduled hook: starts the clock.
	 *
	 * @param mixed ...$args Hook arguments.
	 * @return mixed The first argument, unchanged, in case the hook is also used as a filter.
	 */
	public function before( mixed ...$args ): mixed {
		$hook          = (string) current_action();
		$this->stack[] = array( self::key( $hook, $args ), $hook, microtime( true ), CronInspector::callbacks( $hook ), mb_substr( (string) wp_json_encode( $args ), 0, 300 ) );
		return $args[0] ?? null;
	}

	/**
	 * Last callback on a scheduled hook: records a completed run.
	 *
	 * @param mixed ...$args Hook arguments.
	 * @return mixed The first argument, unchanged.
	 */
	public function after( mixed ...$args ): mixed {
		$frame = array_pop( $this->stack );
		if ( null !== $frame ) {
			$this->record( $frame, 'ok', '' );
		}
		return $args[0] ?? null;
	}

	/**
	 * Shutdown: marks unfinished runs as failed and saves everything once.
	 */
	public function shutdown(): void {
		$error = error_get_last();
		$fatal = is_array( $error ) && in_array( $error['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR ), true );
		while ( $frame = array_pop( $this->stack ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
			$message = $fatal
				? mb_substr( $error['message'], 0, 300 ) . ' in ' . CronInspector::relative( (string) $error['file'] ) . ':' . (int) $error['line']
				: __( 'Did not finish: the request ended early (time limit, exit() or an uncaught exception).', 'sentinel-shield' );
			$this->record( $frame, 'failed', $message );
		}
		$this->save();
	}

	/**
	 * Stores the outcome of one run in memory.
	 *
	 * @param array{0:string, 1:string, 2:float, 3:list<array<string, mixed>>, 4:string} $frame  Run frame.
	 * @param string                                                                     $status ok|failed.
	 * @param string                                                                     $error  Error message.
	 */
	private function record( array $frame, string $status, string $error ): void {
		[ $key, $hook, $start, $callbacks, $args ] = $frame;
		$this->results[ $key ]                     = array(
			'hook'       => $hook,
			'args'       => $args,
			'last_start' => $start,
			'duration'   => round( microtime( true ) - $start, 3 ),
			'status'     => $status,
			'error'      => $error,
			'context'    => $this->context,
			'callbacks'  => $callbacks,
		);
	}

	/**
	 * Merges this request's results into the stored log.
	 */
	private function save(): void {
		$cron_request = 'cron' === $this->context;
		if ( ! $this->results && ! $cron_request ) {
			return;
		}
		$data = get_option( self::OPTION, array() );
		$data = is_array( $data ) ? $data : array();
		$runs = is_array( $data['runs'] ?? null ) ? $data['runs'] : array();
		$now  = time();
		if ( ! $this->results && $now - (int) ( $data['last_request'] ?? 0 ) < MINUTE_IN_SECONDS ) {
			return;
		}
		foreach ( $this->results as $key => $result ) {
			$old                = $runs[ $key ] ?? array();
			$result['count']    = (int) ( $old['count'] ?? 0 ) + 1;
			$result['failures'] = 'ok' === $result['status'] ? 0 : (int) ( $old['failures'] ?? 0 ) + 1;
			$result['last_ok']  = 'ok' === $result['status'] ? (int) $result['last_start'] : (int) ( $old['last_ok'] ?? 0 );
			$runs[ $key ]       = $result;
		}
		if ( count( $runs ) > self::MAX_ENTRIES ) {
			uasort( $runs, static fn( array $a, array $b ): int => (float) $b['last_start'] <=> (float) $a['last_start'] );
			$runs = array_slice( $runs, 0, self::MAX_ENTRIES, true );
		}
		if ( $cron_request ) {
			$data['last_request'] = $now;
		}
		$data['runs'] = $runs;
		update_option( self::OPTION, $data, false );
	}
}
