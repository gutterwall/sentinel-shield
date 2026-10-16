<?php
/**
 * Database schema and versioned migrations.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Install;

defined( 'ABSPATH' ) || exit;

/**
 * Tables are network-wide (base_prefix) because IP rules apply to every site.
 *
 * To change the schema: edit sql(), bump VERSION, and, if existing rows need
 * transforming, add a callback to migrations() keyed by the new version.
 * dbDelta() handles added columns and indexes; migrations handle data.
 */
final class Schema {

	public const VERSION = 1;
	public const OPTION  = 'sentinel_shield_db_version';

	/**
	 * Short table names (without prefix).
	 */
	public const TABLES = array( 'sentinel_ip_rules', 'sentinel_events', 'sentinel_offenses', 'sentinel_unlock_tokens' );

	/**
	 * Installs or upgrades when the stored version is behind. Cheap on every request.
	 */
	public static function maybe_upgrade(): void {
		if ( (int) get_site_option( self::OPTION, 0 ) < self::VERSION ) {
			self::install();
		}
	}

	/**
	 * Runs dbDelta and pending migrations.
	 */
	public static function install(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( self::sql() );

		$from = (int) get_site_option( self::OPTION, 0 );
		foreach ( self::migrations() as $version => $callback ) {
			if ( $version > $from && $version <= self::VERSION ) {
				$callback();
			}
		}
		update_site_option( self::OPTION, self::VERSION );
	}

	/**
	 * Data migrations keyed by schema version. Version 1 is the baseline created by dbDelta.
	 *
	 * @return array<int, callable>
	 */
	private static function migrations(): array {
		return array();
	}

	/**
	 * Fully prefixed table names.
	 *
	 * @return list<string>
	 */
	public static function table_names(): array {
		global $wpdb;
		return array_map( static fn( string $t ): string => $wpdb->base_prefix . $t, self::TABLES );
	}

	/**
	 * CREATE TABLE statements in dbDelta format.
	 *
	 * @return list<string>
	 */
	private static function sql(): array {
		global $wpdb;
		$p       = $wpdb->base_prefix;
		$charset = $wpdb->get_charset_collate();

		return array(
			"CREATE TABLE {$p}sentinel_ip_rules (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  list_type varchar(10) NOT NULL DEFAULT 'block',
  ip_version tinyint(1) unsigned NOT NULL DEFAULT 4,
  ip_start varbinary(16) NOT NULL,
  ip_end varbinary(16) NOT NULL,
  prefix tinyint(3) unsigned NOT NULL DEFAULT 32,
  label varchar(64) NOT NULL DEFAULT '',
  reason varchar(255) NOT NULL DEFAULT '',
  source varchar(32) NOT NULL DEFAULT 'manual',
  created_by bigint(20) unsigned NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  expires_at datetime DEFAULT NULL,
  hits bigint(20) unsigned NOT NULL DEFAULT 0,
  last_hit_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY lookup (list_type,ip_version,ip_start,ip_end),
  KEY expires_at (expires_at),
  KEY source (source)
) $charset;",
			"CREATE TABLE {$p}sentinel_events (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL,
  ip varbinary(16) DEFAULT NULL,
  ip_text varchar(45) NOT NULL DEFAULT '',
  event varchar(32) NOT NULL DEFAULT '',
  module varchar(32) NOT NULL DEFAULT '',
  reason varchar(255) NOT NULL DEFAULT '',
  uri text NULL,
  user_agent varchar(512) NOT NULL DEFAULT '',
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  is_test tinyint(1) unsigned NOT NULL DEFAULT 0,
  context longtext NULL,
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY ip_time (ip,created_at),
  KEY event_time (event,created_at)
) $charset;",
			"CREATE TABLE {$p}sentinel_offenses (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ip varbinary(16) NOT NULL,
  module varchar(32) NOT NULL DEFAULT '',
  reason varchar(255) NOT NULL DEFAULT '',
  is_test tinyint(1) unsigned NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY ip_time (ip,is_test,created_at),
  KEY created_at (created_at)
) $charset;",
			"CREATE TABLE {$p}sentinel_unlock_tokens (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  token_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  ip_text varchar(45) NOT NULL DEFAULT '',
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  used_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY token_hash (token_hash),
  KEY expires_at (expires_at)
) $charset;",
		);
	}
}
