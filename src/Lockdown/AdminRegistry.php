<?php
/**
 * Administrator accounts: discovery straight from the database, and approvals.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * The SC malware creates its administrator by writing to the users tables
 * directly (so no WordPress hooks fire) and then hides it from the user list.
 * Accounts are therefore found with SQL and compared with what WordPress's own
 * user query returns. With the administrator lock on, only approved accounts
 * keep admin rights, however they got them.
 *
 * The approved list normally lives in the database. Defining SENTINEL_SHIELD_ADMINS
 * in wp-config.php replaces it with a fixed list ("admin#1, jane#7": logins, each
 * optionally pinned to a user ID) that database writes cannot change, and makes
 * the lock always enforced.
 */
final class AdminRegistry {

	public const OPTION = 'sentinel_shield_admin_approvals';

	public const CONSTANT = 'SENTINEL_SHIELD_ADMINS';

	/**
	 * Capabilities that amount to control of the site's code.
	 */
	public const POWER_CAPS = array( 'manage_options', 'activate_plugins', 'install_plugins', 'edit_plugins', 'edit_files', 'update_core' );

	/**
	 * Per-request memo of lock decisions.
	 *
	 * @var array<int, bool>
	 */
	private array $locked = array();

	/**
	 * Parsed wp-config.php list (false until read).
	 *
	 * @var list<array{login:string, id:?int}>|null|false
	 */
	private array|null|false $fixed = false;

	/**
	 * Constructor.
	 *
	 * @param string $constant Name of the wp-config.php constant (tests use their own).
	 */
	public function __construct( private string $constant = self::CONSTANT ) {}

	/**
	 * The administrator list from wp-config.php, or null when it is not defined.
	 * Accepts a comma-separated string or an array; "login#ID" pins an entry to
	 * one account so a deleted login cannot be re-registered by someone else.
	 *
	 * @return list<array{login:string, id:?int}>|null
	 */
	public function fixed(): ?array {
		if ( false === $this->fixed ) {
			$this->fixed = defined( $this->constant ) ? self::parse( constant( $this->constant ) ) : null;
		}
		return $this->fixed;
	}

	/**
	 * Whether the list is set in wp-config.php.
	 */
	public function is_fixed(): bool {
		return null !== $this->fixed();
	}

	/**
	 * Parses a SENTINEL_SHIELD_ADMINS value.
	 *
	 * @param mixed $raw String or array.
	 * @return list<array{login:string, id:?int}>
	 */
	public static function parse( mixed $raw ): array {
		$items = is_array( $raw ) ? $raw : explode( ',', is_scalar( $raw ) ? (string) $raw : '' );
		$out   = array();
		foreach ( $items as $item ) {
			$item = trim( is_scalar( $item ) ? (string) $item : '' );
			$id   = null;
			if ( preg_match( '/^(.*?)\s*#\s*(\d+)$/', $item, $m ) ) {
				$item = $m[1];
				$id   = (int) $m[2];
			}
			if ( '' !== $item ) {
				$out[] = array(
					'login' => $item,
					'id'    => $id,
				);
			}
		}
		return $out;
	}

	/**
	 * Each wp-config.php entry with the account it matches and its state:
	 * ok, missing (no such login), id_mismatch (login belongs to another ID)
	 * or not_admin (account exists but has no admin powers; harmless).
	 *
	 * @return list<array{entry:string, login:string, id:?int, user_id:int, state:string}>
	 */
	public function fixed_report(): array {
		$out = array();
		foreach ( (array) $this->fixed() as $entry ) {
			$user  = get_user_by( 'login', $entry['login'] );
			$state = 'ok';
			if ( ! $user instanceof \WP_User ) {
				$state = 'missing';
			} elseif ( null !== $entry['id'] && $entry['id'] !== $user->ID ) {
				$state = 'id_mismatch';
			} elseif ( ! self::is_privileged( $user ) ) {
				$state = 'not_admin';
			}
			$out[] = array(
				'entry'   => $entry['login'] . ( null === $entry['id'] ? '' : '#' . $entry['id'] ),
				'login'   => $entry['login'],
				'id'      => $entry['id'],
				'user_id' => $user instanceof \WP_User ? $user->ID : 0,
				'state'   => $state,
			);
		}
		return $out;
	}

	/**
	 * Whether any list is in force (a wp-config.php list always is, even empty).
	 */
	public function has_list(): bool {
		return $this->is_fixed() || (bool) $this->approvals();
	}

	/**
	 * Whether the lock is enforced, given the "Administrator lock" setting.
	 *
	 * @param bool $setting Setting value.
	 */
	public function enforced( bool $setting ): bool {
		return $this->is_fixed() || ( $setting && $this->has_list() );
	}

	/**
	 * Approved accounts: user ID => [login, at, by].
	 *
	 * @return array<int, array{login:string, at:int, by:int}>
	 */
	public function approvals(): array {
		$list = get_site_option( self::OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Approves an account (bound to its login, so a renamed account needs approving again).
	 *
	 * @param int $user_id User.
	 * @param int $by      Approving user (0 for WP-CLI).
	 */
	public function approve( int $user_id, int $by ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || $this->is_fixed() ) {
			return false;
		}
		$list             = $this->approvals();
		$list[ $user_id ] = array(
			'login' => (string) $user->user_login,
			'at'    => time(),
			'by'    => $by,
		);
		$this->locked     = array();
		return update_site_option( self::OPTION, $list );
	}

	/**
	 * Withdraws approval.
	 *
	 * @param int $user_id User.
	 */
	public function revoke( int $user_id ): bool {
		$list = $this->approvals();
		if ( $this->is_fixed() || ! isset( $list[ $user_id ] ) ) {
			return false;
		}
		unset( $list[ $user_id ] );
		$this->locked = array();
		return update_site_option( self::OPTION, $list );
	}

	/**
	 * Whether an account is approved.
	 *
	 * @param \WP_User $user User.
	 */
	public function is_approved( \WP_User $user ): bool {
		if ( $this->is_fixed() ) {
			foreach ( (array) $this->fixed() as $fixed ) {
				// Logins are unique regardless of case in WordPress's database.
				if ( strtolower( $fixed['login'] ) === strtolower( (string) $user->user_login ) && ( null === $fixed['id'] || $fixed['id'] === $user->ID ) ) {
					return true;
				}
			}
			return false;
		}
		$entry = $this->approvals()[ $user->ID ] ?? null;
		return is_array( $entry ) && (string) $entry['login'] === (string) $user->user_login;
	}

	/**
	 * Whether an account has admin-level power (super admin on multisite).
	 *
	 * @param \WP_User $user User.
	 */
	public static function is_privileged( \WP_User $user ): bool {
		if ( is_multisite() ) {
			return is_super_admin( $user->ID );
		}
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			return true;
		}
		foreach ( self::POWER_CAPS as $cap ) {
			if ( ! empty( $user->allcaps[ $cap ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the administrator lock denies this user. Never locks anyone while
	 * no account is approved in the database, so turning the lock on cannot lock
	 * everyone out; a wp-config.php list is applied as written.
	 *
	 * @param int $user_id User.
	 */
	public function is_locked( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		if ( ! isset( $this->locked[ $user_id ] ) ) {
			$user                     = get_userdata( $user_id );
			$this->locked[ $user_id ] = $user instanceof \WP_User && $this->has_list() && self::is_privileged( $user ) && ! $this->is_approved( $user );
		}
		return $this->locked[ $user_id ];
	}

	/**
	 * Every admin-level account, found in the database, with whether WordPress's
	 * user list shows it and whether it is approved.
	 *
	 * @return list<array{id:int, login:string, email:string, registered:string, roles:list<string>, direct_caps:bool, hidden:bool, approved:bool}>
	 */
	public function privileged_users(): array {
		$ids = $this->privileged_ids();
		if ( ! $ids ) {
			return array();
		}
		$visible = array_map( 'intval', $this->visible_ids( $ids ) );
		$out     = array();
		foreach ( $ids as $id ) {
			$user = get_userdata( $id );
			if ( ! $user instanceof \WP_User ) {
				continue;
			}
			$out[] = array(
				'id'          => $id,
				'login'       => (string) $user->user_login,
				'email'       => (string) $user->user_email,
				'registered'  => (string) $user->user_registered,
				'roles'       => array_values( (array) $user->roles ),
				'direct_caps' => ! is_multisite() && ! in_array( 'administrator', (array) $user->roles, true ),
				'hidden'      => ! in_array( $id, $visible, true ),
				'approved'    => $this->is_approved( $user ),
			);
		}
		return $out;
	}

	/**
	 * Admin-level accounts awaiting approval (only meaningful once some are approved).
	 *
	 * @return list<array<string, mixed>>
	 */
	public function pending(): array {
		if ( ! $this->has_list() ) {
			return array();
		}
		return array_values( array_filter( $this->privileged_users(), static fn( array $u ): bool => ! $u['approved'] ) );
	}

	/**
	 * Approves every admin that WordPress's user list shows (not hidden ones),
	 * plus the given user. Used when the lock is first turned on.
	 *
	 * @param int $by Acting user.
	 * @return int Number approved.
	 */
	public function approve_visible( int $by ): int {
		$count = 0;
		if ( $this->is_fixed() ) {
			return 0;
		}
		foreach ( $this->privileged_users() as $user ) {
			if ( ( ! $user['hidden'] || $user['id'] === $by ) && ! $user['approved'] && $this->approve( $user['id'], $by ) ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * User IDs with admin-level capabilities according to the database itself.
	 *
	 * @return list<int>
	 */
	private function privileged_ids(): array {
		global $wpdb;
		if ( is_multisite() ) {
			$logins = array_filter( array_map( 'strval', get_super_admins() ) );
			if ( ! $logins ) {
				return array();
			}
			$ids = $wpdb->get_col( $wpdb->prepare( 'SELECT ID FROM %i WHERE user_login IN (' . implode( ',', array_fill( 0, count( $logins ), '%s' ) ) . ') ORDER BY ID', array_merge( array( $wpdb->users ), array_values( $logins ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholders are built above; must bypass user query filters.
			return array_map( 'intval', (array) $ids );
		}
		$likes = array( '%' . $wpdb->esc_like( '"administrator"' ) . '%' );
		foreach ( self::POWER_CAPS as $cap ) {
			$likes[] = '%' . $wpdb->esc_like( '"' . $cap . '";b:1' ) . '%';
		}
		$where = implode( ' OR ', array_fill( 0, count( $likes ), 'm.meta_value LIKE %s' ) );
		$ids   = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT u.ID FROM %i u JOIN %i m ON m.user_id = u.ID WHERE m.meta_key = %s AND ( $where ) ORDER BY u.ID", array_merge( array( $wpdb->users, $wpdb->usermeta, $wpdb->get_blog_prefix() . 'capabilities' ), $likes ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $where holds only placeholders; must bypass user query filters.
		return array_map( 'intval', (array) $ids );
	}

	/**
	 * Which of the given IDs WordPress's user list would show, with the same
	 * filters the Users screen applies.
	 *
	 * @param list<int> $ids User IDs.
	 * @return list<int|string>
	 */
	private function visible_ids( array $ids ): array {
		$args = array(
			'include'     => $ids,
			'fields'      => 'ID',
			'number'      => -1,
			'count_total' => false,
			// Super admins need not be members of any site.
			'blog_id'     => is_multisite() ? 0 : get_current_blog_id(),
		);
		$args = (array) apply_filters( 'users_list_table_query_args', $args ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Applies core's filter to see what the Users screen shows.
		return array_values( (array) get_users( $args ) );
	}
}
