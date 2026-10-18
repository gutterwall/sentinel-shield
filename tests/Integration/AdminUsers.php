<?php
/**
 * Test helper: administrator accounts that are privileged on single sites and
 * multisite alike.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

/**
 * On multisite, administrator-level power means super admin (only super admins
 * can install plugins or edit code), so a plain "administrator" role on one site
 * is not privileged there. These helpers create accounts that are.
 */
trait AdminUsers {

	/**
	 * Creates an administrator (a super admin on multisite) and returns its ID.
	 *
	 * @param array<string, mixed> $args Extra user fields.
	 */
	protected static function create_admin( array $args = array() ): int {
		$id = (int) self::factory()->user->create( array_merge( array( 'role' => 'administrator' ), $args ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		return $id;
	}

	/**
	 * Same as create_admin(), returning the user.
	 *
	 * @param array<string, mixed> $args Extra user fields.
	 */
	protected static function create_admin_user( array $args = array() ): \WP_User {
		return get_userdata( self::create_admin( $args ) );
	}

	/**
	 * Gives an existing account administrator-level power.
	 *
	 * @param int $id User ID.
	 */
	protected static function make_admin( int $id ): void {
		( new \WP_User( $id ) )->set_role( 'administrator' );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
	}

	/**
	 * Takes administrator-level power away.
	 *
	 * @param int    $id   User ID.
	 * @param string $role New role.
	 */
	protected static function demote( int $id, string $role = 'editor' ): void {
		if ( is_multisite() ) {
			revoke_super_admin( $id );
		}
		( new \WP_User( $id ) )->set_role( $role );
	}
}
