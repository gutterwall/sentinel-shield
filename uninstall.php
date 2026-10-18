<?php
/**
 * Uninstall: removes all data only when "Delete all data on uninstall" is enabled.
 *
 * @package SentinelShield
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$sentinel_shield_settings = get_site_option( 'sentinel_shield_settings' );
if ( ! is_array( $sentinel_shield_settings ) || empty( $sentinel_shield_settings['general']['delete_data_on_uninstall'] ) ) {
	return;
}

global $wpdb;

foreach ( array( 'sentinel_ip_rules', 'sentinel_events', 'sentinel_offenses', 'sentinel_unlock_tokens', 'sentinel_feed_ranges', 'sentinel_login_attempts' ) as $sentinel_shield_table ) {
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->base_prefix . $sentinel_shield_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SchemaChange -- Uninstall cleanup.
}

foreach ( array( 'sentinel_shield_settings', 'sentinel_shield_db_version', 'sentinel_shield_secret', 'sentinel_shield_cloudflare_ranges', 'sentinel_shield_welcome', 'sentinel_shield_feeds_state', 'sentinel_shield_admin_approvals', 'sentinel_shield_scan_report', 'sentinel_shield_scan_baseline', 'sentinel_shield_geo_db' ) as $sentinel_shield_option ) {
	delete_site_option( $sentinel_shield_option );
}

// Two-factor settings and known login IPs (user meta is shared by the whole network).
$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE meta_key LIKE %s OR meta_key = %s', $wpdb->usermeta, $wpdb->esc_like( '_sentinel_shield_2fa_' ) . '%', '_sentinel_shield_known_ips' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// Transients (single site: options table; multisite: sitemeta).
$sentinel_shield_like  = $wpdb->esc_like( '_site_transient_sentinel_shield_' ) . '%';
$sentinel_shield_tlike = $wpdb->esc_like( '_site_transient_timeout_sentinel_shield_' ) . '%';
if ( is_multisite() ) {
	$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE meta_key LIKE %s OR meta_key LIKE %s', $wpdb->sitemeta, $sentinel_shield_like, $sentinel_shield_tlike ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $sentinel_shield_site_id ) {
		switch_to_blog( (int) $sentinel_shield_site_id );
		delete_option( 'sentinel_shield_site_overrides' );
		delete_option( 'sentinel_shield_cron_runs' );
		delete_option( 'sentinel_shield_cron_paused' );
		wp_clear_scheduled_hook( 'sentinel_shield_maintenance' );
		wp_clear_scheduled_hook( 'sentinel_shield_cf_refresh' );
		wp_clear_scheduled_hook( 'sentinel_shield_feeds_tick' );
		wp_clear_scheduled_hook( 'sentinel_shield_feeds_tick', array( 'soon' ) );
		wp_clear_scheduled_hook( 'sentinel_shield_lockdown_scan' );
		wp_clear_scheduled_hook( 'sentinel_shield_geo_update' );
		wp_clear_scheduled_hook( 'sentinel_shield_geo_update', array( 'soon' ) );
		restore_current_blog();
	}
} else {
	$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s', $wpdb->options, $sentinel_shield_like, $sentinel_shield_tlike ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	wp_clear_scheduled_hook( 'sentinel_shield_maintenance' );
	wp_clear_scheduled_hook( 'sentinel_shield_cf_refresh' );
	wp_clear_scheduled_hook( 'sentinel_shield_feeds_tick' );
	wp_clear_scheduled_hook( 'sentinel_shield_feeds_tick', array( 'soon' ) );
	wp_clear_scheduled_hook( 'sentinel_shield_lockdown_scan' );
	wp_clear_scheduled_hook( 'sentinel_shield_geo_update' );
	wp_clear_scheduled_hook( 'sentinel_shield_geo_update', array( 'soon' ) );
	delete_option( 'sentinel_shield_cron_runs' );
	delete_option( 'sentinel_shield_cron_paused' );
}

// Country database folder (main site's uploads).
if ( is_multisite() ) {
	switch_to_blog( get_main_site_id() );
}
$sentinel_shield_dir = trailingslashit( wp_upload_dir( null, false )['basedir'] ) . 'sentinel-shield';
if ( is_multisite() ) {
	restore_current_blog();
}
foreach ( array( 'geo-country.bin', 'geo-country.bin.new', 'geo-country.bin.new.tmp', 'index.php', '.htaccess' ) as $sentinel_shield_file ) {
	if ( is_file( "$sentinel_shield_dir/$sentinel_shield_file" ) ) {
		wp_delete_file( "$sentinel_shield_dir/$sentinel_shield_file" );
	}
}
if ( is_dir( $sentinel_shield_dir ) ) {
	rmdir( $sentinel_shield_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Removes our own, now empty, folder.
}

wp_cache_delete( 'rules_block', 'sentinel_shield' );
wp_cache_delete( 'rules_allow', 'sentinel_shield' );
wp_cache_delete( 'feed_set', 'sentinel_shield' );
