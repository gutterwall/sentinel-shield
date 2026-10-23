<?php
/**
 * Plugin bootstrap and service wiring.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

use SentinelShield\Admin\Admin;
use SentinelShield\Admin\AdminBar;
use SentinelShield\CLI\Command;
use SentinelShield\Cron\CronControl;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Install\Schema;
use SentinelShield\Geo\CountryDatabase;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Lockdown\RequestGuard;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockout\LockoutService;
use SentinelShield\Lockout\RepositoryBlockWriter;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Modules\CronMonitorModule;
use SentinelShield\Modules\FeedsModule;
use SentinelShield\Modules\IpGateModule;
use SentinelShield\Modules\GeoLoginModule;
use SentinelShield\Modules\LockdownModule;
use SentinelShield\Modules\LoginGuardModule;
use SentinelShield\Modules\LockoutModule;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Modules\TwoFactorModule;
use SentinelShield\Modules\ModuleInterface;
use SentinelShield\Modules\UnlockModule;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Repository\OffenseRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Safety\AdminProtection;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Support\DataDir;
use SentinelShield\Support\OptionPrimer;
use SentinelShield\Support\I18n;
use SentinelShield\TwoFactor\SecretBox;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Unlock\UnlockService;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Audit\AuditExporter;

/**
 * Singleton entry point.
 */
final class Plugin {

	/**
	 * Instance.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Services.
	 *
	 * @var Container
	 */
	private Container $container;

	/**
	 * Boot guard.
	 *
	 * @var bool
	 */
	private bool $booted = false;

	/**
	 * Registered modules.
	 *
	 * @var array<string, ModuleInterface>
	 */
	private array $modules = array();

	/**
	 * The shared instance.
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Builds the container.
	 */
	private function __construct() {
		$this->container = new Container();
		$this->register_services();
	}

	/**
	 * The service container.
	 */
	public function container(): Container {
		return $this->container;
	}

	/**
	 * Modules known to this build (enabled or not).
	 *
	 * @return array<string, ModuleInterface>
	 */
	public function modules(): array {
		return $this->modules;
	}

	/**
	 * Registers service factories.
	 */
	private function register_services(): void {
		$c = $this->container;

		$c->set( Settings::class, static fn(): Settings => new Settings() );
		$c->set( BlockRepository::class, static fn(): BlockRepository => new BlockRepository( $GLOBALS['wpdb'] ) );
		$c->set( EventRepository::class, static fn(): EventRepository => new EventRepository( $GLOBALS['wpdb'] ) );
		$c->set( OffenseRepository::class, static fn(): OffenseRepository => new OffenseRepository( $GLOBALS['wpdb'] ) );
		$c->set( TokenRepository::class, static fn(): TokenRepository => new TokenRepository( $GLOBALS['wpdb'] ) );
		$c->set( CloudflareRanges::class, static fn(): CloudflareRanges => new CloudflareRanges() );
		$c->set( FeedRepository::class, static fn(): FeedRepository => new FeedRepository( $GLOBALS['wpdb'] ) );
		$c->set( AdminRegistry::class, static fn(): AdminRegistry => new AdminRegistry() );
		$c->set( FileIntegrity::class, static fn(): FileIntegrity => new FileIntegrity() );
		$c->set(
			EarlyGate::class,
			static fn( Container $c ): EarlyGate => new EarlyGate(
				$c->get( Settings::class ),
				$c->get( BlockRepository::class ),
				$c->get( RuleCache::class ),
				$c->get( Gate::class ),
				$c->get( SafetyGuard::class ),
				$c->get( ClientIpFactory::class ),
				$c->get( EventRepository::class )
			)
		);
		$c->set( AuditExporter::class, static fn( Container $c ): AuditExporter => new AuditExporter( $c->get( Settings::class ), $c->get( EventRepository::class ) ) );
		$c->set( CloudflareSync::class, static fn( Container $c ): CloudflareSync => new CloudflareSync( $c->get( Settings::class ), $c->get( SecretBox::class ), $c->get( EarlyGate::class ) ) );
		$c->set(
			IntegrityScanner::class,
			static fn( Container $c ): IntegrityScanner => new IntegrityScanner( $c->get( AdminRegistry::class ), $c->get( EventRepository::class ), $c->get( Settings::class ) )
		);
		$c->set(
			Hardening::class,
			static fn( Container $c ): Hardening => new Hardening(
				$c->get( Settings::class ),
				$c->get( AdminRegistry::class ),
				$c->get( EventRepository::class ),
				static fn(): string => (string) $c->get( 'client_ip' )
			)
		);
		$c->set(
			RequestGuard::class,
			static fn( Container $c ): RequestGuard => new RequestGuard(
				$c->get( Settings::class ),
				$c->get( EventRepository::class ),
				static fn(): bool => $c->get( SafetyGuard::class )->is_bypassed(),
				$c->get( Gate::class ),
				static fn(): string => (string) $c->get( 'client_ip' )
			)
		);
		$c->set( CountryDatabase::class, static fn(): CountryDatabase => new CountryDatabase( GeoUpdater::path() ) );
		$c->set(
			GeoUpdater::class,
			static fn( Container $c ): GeoUpdater => new GeoUpdater( $c->get( Settings::class ), $c->get( CountryDatabase::class ), $c->get( EventRepository::class ) )
		);
		$c->set(
			GeoResolver::class,
			static fn( Container $c ): GeoResolver => new GeoResolver(
				$c->get( Settings::class ),
				$c->get( CountryDatabase::class ),
				$_SERVER, // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only two-letter codes that match the country list are used.
				static fn(): array => (array) $c->get( 'client_ip_details' )
			)
		);
		$c->set(
			LoginGeoGuard::class,
			static fn( Container $c ): LoginGeoGuard => new LoginGeoGuard(
				$c->get( Settings::class ),
				$c->get( GeoResolver::class ),
				$c->get( Gate::class ),
				$c->get( EventRepository::class ),
				static fn(): string => (string) $c->get( 'client_ip' ),
				static fn(): bool => (bool) $c->get( 'client_ip_details' )['fallback']
			)
		);
		$c->set( LoginAttemptRepository::class, static fn(): LoginAttemptRepository => new LoginAttemptRepository( $GLOBALS['wpdb'] ) );
		$c->set(
			BruteForceGuard::class,
			static fn( Container $c ): BruteForceGuard => new BruteForceGuard(
				$c->get( Settings::class ),
				$c->get( LoginAttemptRepository::class ),
				$c->get( Gate::class ),
				$c->get( EventRepository::class ),
				static fn(): string => (string) $c->get( 'client_ip' ),
				static fn(): bool => (bool) $c->get( 'client_ip_details' )['fallback'],
				static fn( string $ip, string $module, string $reason ) => LockoutModule::apply( $c, $ip, $module, $reason )
			)
		);
		// The key comes from wp-config.php salts, so it is derived when first needed (after pluggable.php).
		$c->set( SecretBox::class, static fn(): SecretBox => new SecretBox( static fn(): string => wp_salt( 'auth' ) ) );
		$c->set( UserTwoFactor::class, static fn( Container $c ): UserTwoFactor => new UserTwoFactor( $c->get( SecretBox::class ) ) );
		$c->set(
			TwoFactorLogin::class,
			static fn( Container $c ): TwoFactorLogin => new TwoFactorLogin(
				$c->get( Settings::class ),
				$c->get( UserTwoFactor::class ),
				$c->get( SecretBox::class ),
				$c->get( EventRepository::class ),
				static fn(): string => (string) $c->get( 'client_ip' )
			)
		);
		$c->set( RuleCache::class, static fn( Container $c ): RuleCache => new RuleCache( $c->get( BlockRepository::class ), $c->get( FeedRepository::class ) ) );
		$c->set(
			FeedUpdater::class,
			static fn( Container $c ): FeedUpdater => new FeedUpdater(
				$c->get( Settings::class ),
				$c->get( FeedRepository::class ),
				$c->get( RuleCache::class ),
				$c->get( EventRepository::class )
			)
		);
		$c->set(
			ClientIpFactory::class,
			static fn( Container $c ): ClientIpFactory => new ClientIpFactory( $c->get( Settings::class ), $c->get( CloudflareRanges::class ) )
		);
		// The current request's client IP, resolved once.
		$c->set( 'client_ip_details', static fn( Container $c ): array => $c->get( ClientIpFactory::class )->from_globals()->details() );
		$c->set( 'client_ip', static fn( Container $c ): string => (string) $c->get( 'client_ip_details' )['ip'] );
		$c->set(
			SafetyGuard::class,
			static fn( Container $c ): SafetyGuard => new SafetyGuard( $c->get( Settings::class ), $_SERVER ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Values are validated as IPs.
		);
		$c->set(
			Gate::class,
			static fn( Container $c ): Gate => new Gate(
				$c->get( Settings::class ),
				$c->get( RuleCache::class ),
				$c->get( BlockRepository::class ),
				$c->get( EventRepository::class ),
				$c->get( SafetyGuard::class ),
				static fn(): string => (string) $c->get( 'client_ip' ),
				$c->get( FeedRepository::class ),
				static fn(): bool => (bool) $c->get( 'client_ip_details' )['fallback']
			)
		);
		$c->set(
			LockoutService::class,
			static function ( Container $c ): LockoutService {
				$settings = $c->get( Settings::class );
				$gate     = $c->get( Gate::class );
				return new LockoutService(
					$c->get( OffenseRepository::class ),
					new RepositoryBlockWriter( $c->get( BlockRepository::class ), $c->get( RuleCache::class ) ),
					static fn( string $ip ): bool => $gate->is_protected( $ip ),
					static fn( string $module ): bool => $settings->is_test_mode_chain( $module, 'lockout' ),
					$settings->lockout_durations(),
					$settings->lockout_window(),
					$settings->is_enabled() && $settings->is_module_enabled( 'lockout' )
				);
			}
		);
		$c->set(
			Unblocker::class,
			static fn( Container $c ): Unblocker => new Unblocker(
				$c->get( BlockRepository::class ),
				$c->get( RuleCache::class ),
				$c->get( OffenseRepository::class ),
				$c->get( EventRepository::class )
			)
		);
		$c->set(
			AdminProtection::class,
			static fn( Container $c ): AdminProtection => new AdminProtection(
				$c->get( BlockRepository::class ),
				$c->get( RuleCache::class ),
				$c->get( Gate::class ),
				$c->get( EventRepository::class )
			)
		);
		$c->set(
			UnlockService::class,
			static fn( Container $c ): UnlockService => new UnlockService(
				$c->get( Settings::class ),
				$c->get( TokenRepository::class ),
				$c->get( Unblocker::class ),
				$c->get( EventRepository::class ),
				$c->get( Gate::class ),
				static fn(): string => (string) $c->get( 'client_ip' )
			)
		);
	}

	/**
	 * Boots modules, admin and CLI. Called once from the main plugin file.
	 */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		// What every request reads, in one query instead of one each.
		$cached = array();
		foreach ( array( 'rules_allow', 'rules_block', 'rules_allow_login' ) as $key ) {
			$cached[] = '_site_transient_sentinel_shield_' . $key;
			$cached[] = '_site_transient_timeout_sentinel_shield_' . $key;
		}
		OptionPrimer::prime( array_merge( array( Settings::OPTION, Schema::OPTION, DataDir::ROOT, EarlyGate::LEGACY ), wp_using_ext_object_cache() ? array() : $cached ) );
		Schema::maybe_upgrade();
		// WP-CLI and cron have no document root; remember the web server's.
		DataDir::remember_document_root();

		$this->modules = array(
			'ip_gate'      => new IpGateModule(),
			'lockout'      => new LockoutModule(),
			'unlock'       => new UnlockModule(),
			'feeds'        => new FeedsModule(),
			'cron_monitor' => new CronMonitorModule(),
			'lockdown'     => new LockdownModule(),
			'geo_login'    => new GeoLoginModule(),
			'login_guard'  => new LoginGuardModule(),
			'two_factor'   => new TwoFactorModule(),
		);

		( new MaintenanceModule() )->register( $this->container );
		// Always hooked: the snapshot must follow rule and settings changes even with modules off.
		$this->container->get( EarlyGate::class )->register();
		$this->container->get( CloudflareSync::class )->register();
		$this->container->get( AuditExporter::class )->register();
		CronControl::register_guard();
		$container = $this->container;
		add_action( 'sentinel_shield_settings_saved', static fn() => LockdownModule::on_settings_saved( $container ) );
		add_action( 'sentinel_shield_settings_saved', static fn() => GeoLoginModule::on_settings_saved( $container ) );

		$settings = $this->container->get( Settings::class );
		if ( $settings->is_enabled() ) {
			foreach ( $this->modules as $slug => $module ) {
				if ( $settings->is_module_enabled( $slug ) ) {
					$module->register( $this->container );
				}
			}
		}

		// A wp-config.php administrator list holds even when protection or the
		// lockdown module is switched off in the database.
		if ( ! SafetyGuard::emergency_disabled() && $this->container->get( AdminRegistry::class )->is_fixed() ) {
			$this->container->get( Hardening::class )->register_admin_lock();
		}

		add_action( 'init', array( I18n::class, 'load' ) );
		( new AdminBar( $this->container ) )->register();

		if ( is_admin() ) {
			( new Admin( $this->container ) )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			Command::register( $this->container );
		}
	}
}
