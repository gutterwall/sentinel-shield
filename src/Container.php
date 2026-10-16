<?php
/**
 * Minimal service container.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield;

defined( 'ABSPATH' ) || exit;

/**
 * Lazily builds shared services from registered factories.
 */
final class Container {

	/**
	 * Factories keyed by service ID.
	 *
	 * @var array<string, callable>
	 */
	private array $factories = array();

	/**
	 * Built instances keyed by service ID.
	 *
	 * @var array<string, mixed>
	 */
	private array $instances = array();

	/**
	 * Registers (or replaces) a factory. The factory receives the container.
	 *
	 * @param string   $id      Service ID.
	 * @param callable $factory Factory.
	 */
	public function set( string $id, callable $factory ): void {
		$this->factories[ $id ] = $factory;
		unset( $this->instances[ $id ] );
	}

	/**
	 * Registers a ready-made instance (handy in tests).
	 *
	 * @param string $id    Service ID.
	 * @param mixed  $value Instance.
	 */
	public function instance( string $id, mixed $value ): void {
		$this->instances[ $id ] = $value;
	}

	/**
	 * Whether a service is known.
	 *
	 * @param string $id Service ID.
	 */
	public function has( string $id ): bool {
		return isset( $this->factories[ $id ] ) || array_key_exists( $id, $this->instances );
	}

	/**
	 * Returns the shared instance, building it on first use.
	 *
	 * @param string $id Service ID.
	 * @throws \OutOfBoundsException When the service is unknown.
	 */
	public function get( string $id ): mixed {
		if ( array_key_exists( $id, $this->instances ) ) {
			return $this->instances[ $id ];
		}
		if ( ! isset( $this->factories[ $id ] ) ) {
			throw new \OutOfBoundsException( esc_html( sprintf( 'Service "%s" is not registered.', $id ) ) );
		}
		$this->instances[ $id ] = ( $this->factories[ $id ] )( $this );
		return $this->instances[ $id ];
	}
}
