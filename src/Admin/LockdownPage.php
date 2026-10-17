<?php
/**
 * Malware lockdown page: SC malware scan results, administrator approvals and hardening status.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockdown\UploadGuard;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;

defined( 'ABSPATH' ) || exit;

/**
 * Everything here is read-only except the buttons, which post to Actions::lockdown().
 */
final class LockdownPage {

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
		$settings = $this->c->get( Settings::class );
		$report   = IntegrityScanner::report();

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Malware Lockdown', 'sentinel-shield' ) . '</h1>';
		echo '<p>' . esc_html__( 'Protection against the "SC" WordPress malware described by Sucuri in September 2026 and similar takeovers. SC keeps copies of itself in about eight places at once (a PHP auto-prepend loader, drop-ins, a must-use and a regular plugin, the theme, a ZIP bundle, the database and shared memory), creates a hidden administrator, captures logins, disables security plugins and takes orders from an Ethereum smart contract. Each copy restores the others, so it has to be found and removed everywhere in one go.', 'sentinel-shield' ) . '</p>';

		if ( ! $settings->is_enabled() || ! $settings->is_module_enabled( 'lockdown' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The Malware lockdown module (or protection as a whole) is switched off, so none of the measures below are enforced and the twice-daily scan does not run. You can still scan by hand.', 'sentinel-shield' ) . '</p></div>';
		}

		$this->measures( $settings );
		$this->scan( $report );
		$this->admins( $settings );
		$this->server_rules( $settings );
		$this->cleanup( $report );
		echo '</div>';
	}

	/**
	 * Which lockdown measures are on.
	 *
	 * @param Settings $settings Settings.
	 */
	private function measures( Settings $settings ): void {
		echo '<div class="ss-card"><h2>' . esc_html__( 'Lockdown measures', 'sentinel-shield' ) . '</h2><table class="widefat striped"><tbody>';
		foreach ( SettingsSchema::fields() as $field ) {
			if ( 'lockdown' !== $field['tab'] ) {
				continue;
			}
			$on = (bool) $settings->get( (string) $field['key'], false ) || ( 'lockdown.admin_lock' === $field['key'] && $this->c->get( AdminRegistry::class )->is_fixed() );
			echo '<tr><td style="width:9em">' . View::pill( $on ? __( 'On', 'sentinel-shield' ) : __( 'Off', 'sentinel-shield' ), $on ? 'ok' : ( true === $field['recommended'] ? 'warn' : 'info' ) ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '<td><strong>' . esc_html( (string) $field['label'] ) . '</strong><br><span class="description">' . esc_html( (string) $field['help'] ) . '</span></td></tr>';
		}
		echo '</tbody></table><p><a class="button button-primary" href="' . esc_url( Admin::url( 'sentinel-shield-settings', array( 'tab' => 'lockdown' ) ) ) . '">' . esc_html__( 'Change lockdown settings', 'sentinel-shield' ) . '</a></p></div>';
	}

	/**
	 * Scan summary and findings grouped by check.
	 *
	 * @param array<string, mixed>|null $report Last report.
	 */
	private function scan( ?array $report ): void {
		echo '<div class="ss-card" id="ss-scan"><h2>' . esc_html__( 'Malware scan', 'sentinel-shield' ) . '</h2>';
		View::form_open( 'lockdown' );
		echo '<input type="hidden" name="op" value="scan">';
		if ( null === $report ) {
			echo '<p>' . esc_html__( 'No scan has run yet. The scan only reads files and the database; it never changes or deletes anything.', 'sentinel-shield' ) . '</p>';
		} else {
			$counts = array_count_values( array_column( (array) $report['findings'], 'severity' ) );
			echo '<p>';
			/* translators: 1: date and time, 2: seconds. */
			echo esc_html( sprintf( __( 'Last scan: %1$s (took %2$s s).', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $report['time'] ), number_format_i18n( (float) $report['duration'], 1 ) ) ) . ' ';
			$labels = array(
				'critical' => array( __( 'critical', 'sentinel-shield' ), 'bad' ),
				'warning'  => array( __( 'warnings', 'sentinel-shield' ), 'warn' ),
				'notice'   => array( __( 'to review', 'sentinel-shield' ), 'info' ),
				'ok'       => array( __( 'approved', 'sentinel-shield' ), 'ok' ),
			);
			foreach ( $labels as $severity => [ $label, $state ] ) {
				echo View::pill( number_format_i18n( (int) ( $counts[ $severity ] ?? 0 ) ) . ' ' . $label, ( $counts[ $severity ] ?? 0 ) ? $state : 'ok' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			echo '</p>';
			if ( $report['truncated'] ) {
				echo '<p class="description">' . esc_html__( 'Some checks stopped early because of the size of the site; the rest of their results are not shown.', 'sentinel-shield' ) . '</p>';
			}
		}
		submit_button( __( 'Run scan now', 'sentinel-shield' ), 'primary', 'submit', false );
		echo '</form>';
		if ( null !== $report ) {
			$this->findings( (array) $report['findings'] );
		}
		echo '</div>';
	}

	/**
	 * Findings table.
	 *
	 * @param list<array<string, mixed>> $findings Findings.
	 */
	private function findings( array $findings ): void {
		$states = array(
			'critical' => array( __( 'Critical', 'sentinel-shield' ), 'bad' ),
			'warning'  => array( __( 'Warning', 'sentinel-shield' ), 'warn' ),
			'notice'   => array( __( 'Review', 'sentinel-shield' ), 'info' ),
			'ok'       => array( __( 'Approved', 'sentinel-shield' ), 'ok' ),
		);
		$rank   = array_flip( IntegrityScanner::SEVERITIES );
		echo '<div class="ss-scroll"><table class="widefat ss-scan"><thead><tr><th>' . esc_html__( 'Check', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Result', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		foreach ( IntegrityScanner::checks() as $check => [ $label, $why ] ) {
			$mine = array_values( array_filter( $findings, static fn( array $f ): bool => $f['check'] === $check ) );
			usort( $mine, static fn( array $a, array $b ): int => $rank[ $a['severity'] ] <=> $rank[ $b['severity'] ] );
			$worst = $mine ? (string) $mine[0]['severity'] : 'ok';
			echo '<tr><td style="width:16em"><strong>' . esc_html( $label ) . '</strong><br>';
			echo View::pill( $mine ? $states[ $worst ][0] : __( 'Nothing found', 'sentinel-shield' ), $states[ $worst ][1] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '<br><span class="description">' . esc_html( $why ) . '</span></td><td>';
			if ( ! $mine ) {
				echo '<span class="description">' . esc_html__( 'Nothing suspicious.', 'sentinel-shield' ) . '</span>';
			}
			$approved = array_filter( $mine, static fn( array $f ): bool => ! empty( $f['approved'] ) );
			foreach ( $mine as $finding ) {
				if ( empty( $finding['approved'] ) ) {
					$this->finding( $finding, $states );
				}
			}
			if ( $approved ) {
				/* translators: %d: count. */
				echo '<details><summary>' . esc_html( sprintf( _n( '%d approved item', '%d approved items', count( $approved ), 'sentinel-shield' ), count( $approved ) ) ) . '</summary>';
				foreach ( $approved as $finding ) {
					$this->finding( $finding, $states );
				}
				echo '</details>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * One finding with its approve/unapprove button.
	 *
	 * @param array<string, mixed>                     $finding Finding.
	 * @param array<string, array{0:string, 1:string}> $states  Severity labels.
	 */
	private function finding( array $finding, array $states ): void {
		echo '<div class="ss-finding"><p>' . View::pill( $states[ $finding['severity'] ][0], $states[ $finding['severity'] ][1] ) . ' <strong>' . esc_html( (string) $finding['title'] ) . '</strong></p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		echo '<p class="description">' . esc_html( (string) $finding['detail'] ) . '</p>';
		if ( '' !== (string) $finding['hash'] ) {
			View::form_open( 'lockdown' );
			echo '<input type="hidden" name="id" value="' . esc_attr( (string) $finding['id'] ) . '">';
			if ( ! empty( $finding['approved'] ) ) {
				echo '<input type="hidden" name="op" value="unapprove"><button class="button button-small">' . esc_html__( 'Withdraw approval', 'sentinel-shield' ) . '</button>';
			} else {
				$confirm = 'critical' === $finding['original']
					? __( 'This item matched known malware traits. Approve it only if you are sure it is legitimate. Approve?', 'sentinel-shield' )
					: __( 'Approve this item? You will be warned again if it changes.', 'sentinel-shield' );
				echo '<input type="hidden" name="op" value="approve"><button class="button button-small" onclick="return confirm(' . esc_attr( (string) wp_json_encode( $confirm ) ) . ')">' . esc_html__( 'I recognize this: approve', 'sentinel-shield' ) . '</button>';
			}
			echo '</form>';
		}
		echo '</div>';
	}

	/**
	 * Administrator accounts and approvals.
	 *
	 * @param Settings $settings Settings.
	 */
	private function admins( Settings $settings ): void {
		$registry = $this->c->get( AdminRegistry::class );
		$users    = $registry->privileged_users();
		$lock     = (bool) $settings->get( 'lockdown.admin_lock', false );
		$fixed    = $registry->is_fixed();
		$active   = $registry->enforced( $lock );
		echo '<div class="ss-card" id="ss-admins"><h2>' . esc_html__( 'Administrators', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Every account with administrator powers, read straight from the database, so accounts hidden from the Users screen show up here too.', 'sentinel-shield' ) . ' ';
		if ( $fixed ) {
			echo esc_html__( 'The approved list is fixed in wp-config.php (SENTINEL_SHIELD_ADMINS) and always enforced, whatever the settings say. Approvals cannot be changed here; edit wp-config.php instead.', 'sentinel-shield' );
		} else {
			echo esc_html(
				$active
					? __( 'The administrator lock is on: accounts that are not approved have no admin rights.', 'sentinel-shield' )
					: ( $lock ? __( 'The administrator lock is on but no account is approved yet, so it is not enforced.', 'sentinel-shield' ) : __( 'The administrator lock is off; approvals take effect when you turn it on.', 'sentinel-shield' ) )
			);
		}
		echo '</p>';
		if ( $fixed ) {
			$this->fixed_list( $registry );
		}
		echo '<div class="ss-scroll"><table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Account', 'sentinel-shield' ), __( 'Registered', 'sentinel-shield' ), __( 'Status', 'sentinel-shield' ), __( 'Approval', 'sentinel-shield' ) ) as $heading ) {
			echo '<th>' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $users as $user ) {
			echo '<tr><td><strong>' . esc_html( $user['login'] ) . '</strong> <span class="description">(ID ' . (int) $user['id'] . ')</span><br>' . esc_html( $user['email'] ) . '</td>';
			echo '<td>' . esc_html( $user['registered'] ) . '</td><td>';
			if ( $user['hidden'] ) {
				echo View::pill( __( 'Hidden from Users screen', 'sentinel-shield' ), 'bad' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			if ( $user['direct_caps'] ) {
				echo View::pill( __( 'Admin powers without admin role', 'sentinel-shield' ), 'warn' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			echo $user['approved'] ? View::pill( __( 'Approved', 'sentinel-shield' ), 'ok' ) : View::pill( $active ? __( 'Locked: waiting for approval', 'sentinel-shield' ) : __( 'Not approved', 'sentinel-shield' ), $active ? 'bad' : 'info' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '</td><td>';
			if ( $fixed ) {
				echo '<span class="description">' . esc_html( $user['approved'] ? __( 'Listed in wp-config.php', 'sentinel-shield' ) : __( 'Not listed in wp-config.php', 'sentinel-shield' ) ) . '</span></td></tr>';
				continue;
			}
			$self = get_current_user_id() === $user['id'];
			View::form_open( 'lockdown' );
			echo '<input type="hidden" name="user_id" value="' . (int) $user['id'] . '">';
			if ( $user['approved'] ) {
				echo '<input type="hidden" name="op" value="revoke_admin"><button class="button button-small"' . disabled( $self, true, false ) . '>' . esc_html__( 'Withdraw approval', 'sentinel-shield' ) . '</button>';
				if ( $self ) {
					echo '<br><span class="description">' . esc_html__( 'You cannot withdraw your own approval.', 'sentinel-shield' ) . '</span>';
				}
			} else {
				$confirm = $user['hidden']
					? __( 'This account is hidden from the Users screen, which is how SC hides its administrator. Approve it anyway?', 'sentinel-shield' )
					: __( 'Give this account administrator rights under the lock?', 'sentinel-shield' );
				echo '<input type="hidden" name="op" value="approve_admin"><button class="button button-small" onclick="return confirm(' . esc_attr( (string) wp_json_encode( $confirm ) ) . ')">' . esc_html__( 'Approve', 'sentinel-shield' ) . '</button>';
			}
			echo '</form></td></tr>';
		}
		echo '</tbody></table></div>';
		View::form_open( 'lockdown' );
		echo '<input type="hidden" name="op" value="logout_all"><p>';
		echo '<button class="button" onclick="return confirm(' . esc_attr( (string) wp_json_encode( __( 'Log out every user, including you?', 'sentinel-shield' ) ) ) . ')">' . esc_html__( 'Log out everyone', 'sentinel-shield' ) . '</button> ';
		echo '<span class="description">' . esc_html__( 'Ends every login session. SC steals session tokens and forges login cookies, so after a cleanup also replace the security keys (salts) in wp-config.php, which invalidates forged cookies.', 'sentinel-shield' ) . '</span></p></form>';
		echo '</div>';
	}

	/**
	 * The SENTINEL_SHIELD_ADMINS entries and whether each matches an account.
	 *
	 * @param AdminRegistry $registry Registry.
	 */
	private function fixed_list( AdminRegistry $registry ): void {
		$report = $registry->fixed_report();
		if ( ! $report ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'SENTINEL_SHIELD_ADMINS lists no accounts, so every administrator is locked. Add logins to it in wp-config.php, or remove the line to manage approvals here.', 'sentinel-shield' ) . '</p></div>';
			return;
		}
		$states = array(
			'ok'          => array( __( 'Matches an administrator', 'sentinel-shield' ), 'ok' ),
			'not_admin'   => array( __( 'Account is not an administrator (no effect)', 'sentinel-shield' ), 'info' ),
			'missing'     => array( __( 'No such login: anyone who registers it becomes an approved administrator', 'sentinel-shield' ), 'bad' ),
			'id_mismatch' => array( __( 'Login belongs to a different user ID: not approved', 'sentinel-shield' ), 'bad' ),
		);
		echo '<table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'wp-config.php entry', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Status', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		foreach ( $report as $entry ) {
			echo '<tr><td><code>' . esc_html( $entry['entry'] ) . '</code>';
			if ( 'ok' === $entry['state'] && null === $entry['id'] ) {
				/* translators: %s: suggested entry. */
				echo '<br><span class="description">' . esc_html( sprintf( __( 'Tip: pin it as %s', 'sentinel-shield' ), $entry['login'] . '#' . $entry['user_id'] ) ) . '</span>';
			}
			echo '</td><td>' . View::pill( $states[ $entry['state'] ][0], $states[ $entry['state'] ][1] ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</tbody></table>';
	}

	/**
	 * Uploads rules and wp-config recommendations.
	 *
	 * @param Settings $settings Settings.
	 */
	private function server_rules( Settings $settings ): void {
		global $is_apache;
		echo '<div class="ss-card"><h2>' . esc_html__( 'Server configuration', 'sentinel-shield' ) . '</h2><ul class="ss-list">';
		if ( $settings->get( 'lockdown.block_php_uploads', false ) ) {
			if ( UploadGuard::htaccess_installed() ) {
				echo '<li>' . View::pill( __( 'In place', 'sentinel-shield' ), 'ok' ) . ' ' . esc_html__( 'uploads/.htaccess stops PHP from running in uploads (Apache and LiteSpeed).', 'sentinel-shield' ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			} else {
				echo '<li>' . View::pill( __( 'Missing', 'sentinel-shield' ), 'warn' ) . ' ' . esc_html__( 'uploads/.htaccess could not be written. Save the lockdown settings again, or check folder permissions.', 'sentinel-shield' ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			if ( empty( $is_apache ) ) {
				echo '<li>' . esc_html__( 'This server does not look like Apache, so .htaccess may be ignored. For nginx, add this to the server block:', 'sentinel-shield' ) . '<br><code>' . esc_html( UploadGuard::nginx_rule() ) . '</code></li>';
			}
		}
		$editor = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || $settings->get( 'lockdown.disable_file_editor', false );
		echo '<li>' . View::pill( $editor ? __( 'Off', 'sentinel-shield' ) : __( 'On', 'sentinel-shield' ), $editor ? 'ok' : 'warn' ) . ' ' . esc_html__( 'Built-in file editor.', 'sentinel-shield' ) . ' ' . esc_html__( 'Adding define( \'DISALLOW_FILE_EDIT\', true ); to wp-config.php turns it off even if this plugin is removed.', 'sentinel-shield' ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		echo '<li>' . esc_html__( 'Keep WordPress, plugins and themes updated: most infections start from a known, already-fixed vulnerability.', 'sentinel-shield' ) . '</li>';
		echo '<li>' . esc_html__( 'Fresh security keys for wp-config.php:', 'sentinel-shield' ) . ' <code>https://api.wordpress.org/secret-key/1.1/salt/</code></li>';
		echo '</ul></div>';
	}

	/**
	 * Safe cleanup order (from Sucuri's analysis); open when something critical was found.
	 *
	 * @param array<string, mixed>|null $report Last report.
	 */
	private function cleanup( ?array $report ): void {
		$critical = null !== $report && in_array( 'critical', array_column( (array) $report['findings'], 'severity' ), true );
		echo '<div class="ss-card"><details' . ( $critical ? ' open' : '' ) . '><summary><strong>' . esc_html__( 'If the scan finds SC: cleanup order', 'sentinel-shield' ) . '</strong></summary>';
		echo '<p>' . esc_html__( 'Order matters: delete files first and the remaining copies write them back. Take a full backup (files and database) before you start, and consider your host\'s or a professional cleanup service.', 'sentinel-shield' ) . '</p><ol>';
		$steps = array(
			__( 'Put the site in maintenance mode or block visitors, and keep a forensic copy.', 'sentinel-shield' ),
			__( 'Neutralize the auto-prepend loader: replace the file it points to with an empty "<?php" file, then remove the auto_prepend_file line from .user.ini, php.ini or .htaccess, then restart PHP. PHP caches this setting, so deleting the file first takes the whole site down.', 'sentinel-shield' ),
			__( 'Remove the off-disk copies: the encoded option row, the sc_ options and transients, and (via your host) the shared memory segment.', 'sentinel-shield' ),
			__( 'Pause or delete the malicious scheduled tasks (Scheduled Tasks page) and drop any database triggers on the user tables.', 'sentinel-shield' ),
			__( 'Delete the hidden administrator account and log out everyone.', 'sentinel-shield' ),
			__( 'In one pass, delete the hidden loader and shim, both copies of the fake plugin (must-use and regular), the ZIP bundle and the infected drop-ins; remove only the marked block from functions.php.', 'sentinel-shield' ),
			__( 'Replace WordPress core and reinstall plugins and themes from clean copies; change every password, the database password and the security keys (salts).', 'sentinel-shield' ),
			__( 'Run the scan again. Anything that comes back means a copy is still active somewhere.', 'sentinel-shield' ),
		);
		foreach ( $steps as $step ) {
			echo '<li>' . esc_html( $step ) . '</li>';
		}
		echo '</ol></details></div>';
	}
}
