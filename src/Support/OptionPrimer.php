<?php
/**
 * Loads the plugin's per-request options in one query.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Network options are never autoloaded (on a single site WordPress stores
 * them with autoload off), so every one the plugin reads on a request costs
 * a query of its own. Priming fetches them together into the options cache,
 * where get_site_option() then finds them (missing ones are noted as
 * missing, as WordPress itself does). With a persistent object cache most
 * are already cached and nothing is queried.
 */
final class OptionPrimer {

	/**
	 * Primes network options.
	 *
	 * @param list<string> $names Option names.
	 */
	public static function prime( array $names ): void {
		if ( ! $names ) {
			return;
		}
		if ( ! is_multisite() ) {
			if ( function_exists( 'wp_prime_option_caches' ) ) {
				wp_prime_option_caches( $names );
			}
			return;
		}
		if ( function_exists( 'wp_prime_network_option_caches' ) ) {
			wp_prime_network_option_caches( get_current_network_id(), $names );
			return;
		}
		// WordPress before 6.6: the same, by hand.
		global $wpdb;
		$network = get_current_network_id();
		$missing = array_values( array_filter( $names, static fn( string $name ): bool => false === wp_cache_get( "$network:$name", 'site-options' ) ) );
		if ( ! $missing ) {
			return;
		}
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT meta_key, meta_value FROM %i WHERE site_id = %d AND meta_key IN (' . implode( ',', array_fill( 0, count( $missing ), '%s' ) ) . ')', $wpdb->sitemeta, $network, ...$missing ) ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Placeholders built above; this fills the cache.
		$found = array();
		foreach ( (array) $rows as $row ) {
			$found[ $row->meta_key ] = true;
			wp_cache_add( "$network:{$row->meta_key}", maybe_unserialize( $row->meta_value ), 'site-options' );
		}
		$absent = array_diff( $missing, array_keys( $found ) );
		if ( $absent ) {
			$notoptions = wp_cache_get( "$network:notoptions", 'site-options' );
			$notoptions = is_array( $notoptions ) ? $notoptions : array();
			foreach ( $absent as $name ) {
				$notoptions[ $name ] = true;
			}
			wp_cache_set( "$network:notoptions", $notoptions, 'site-options' );
		}
	}
}
