<?php
/**
 * Resumable, sorted directory walk.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Visits every file under a folder in a fixed order (names sorted byte-wise,
 * depth first), so a walk that stops at a time or file limit can continue
 * later from the last relative path it handled. Folder symlinks are not
 * followed (they could loop or leave the site) and are counted instead.
 */
final class FileWalk {

	/**
	 * Relative path of the last file visited.
	 *
	 * @var string
	 */
	public string $cursor = '';

	/**
	 * Files visited in this call.
	 *
	 * @var int
	 */
	public int $files = 0;

	/**
	 * Folders that could not be read (relative paths).
	 *
	 * @var list<string>
	 */
	public array $unreadable = array();

	/**
	 * Folder symlinks that were not followed (relative paths).
	 *
	 * @var list<string>
	 */
	public array $links = array();

	/**
	 * Visitor: fn( string $absolute, string $relative ): void.
	 *
	 * @var callable
	 */
	private $visit;

	/**
	 * Stop test, asked before each file: fn(): bool.
	 *
	 * @var callable
	 */
	private $stop;

	/**
	 * Constructor.
	 *
	 * @param string       $root Folder to walk.
	 * @param list<string> $skip Relative folder paths not to enter.
	 */
	public function __construct( private string $root, private array $skip = array() ) {
		$this->root = rtrim( wp_normalize_path( $root ), '/' );
	}

	/**
	 * Walks from just after $after ('' = from the start).
	 *
	 * @param string   $after Relative path of the last file handled before.
	 * @param callable $visit fn( string $absolute, string $relative ): void.
	 * @param callable $stop  fn(): bool; true stops before the next file.
	 * @return bool True when the walk reached the end, false when it stopped early.
	 */
	public function run( string $after, callable $visit, callable $stop ): bool {
		$this->visit  = $visit;
		$this->stop   = $stop;
		$this->cursor = $after;
		$this->files  = 0;
		$parts        = '' === $after ? array() : explode( '/', $after );
		return $this->dir( $this->root, '', $parts );
	}

	/**
	 * Walks one folder.
	 *
	 * @param string       $abs   Absolute folder path.
	 * @param string       $rel   Relative folder path ('' for the root).
	 * @param list<string> $after Remaining parts of the resume path.
	 */
	private function dir( string $abs, string $rel, array $after ): bool {
		$names = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable folders are reported.
		if ( false === $names ) {
			$this->unreadable[] = '' === $rel ? '.' : $rel;
			return true;
		}
		sort( $names, SORT_STRING );
		$first = $after[0] ?? null;
		foreach ( $names as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			// Entries before the resume path were handled last time; the one on
			// it is either the last file handled or the folder to resume inside.
			$on_path = false;
			if ( null !== $first ) {
				$order = strcmp( $name, $first );
				if ( $order < 0 ) {
					continue;
				}
				$on_path = 0 === $order;
				$first   = null;
			}
			$path = $abs . '/' . $name;
			$sub  = '' === $rel ? $name : $rel . '/' . $name;
			if ( is_dir( $path ) ) {
				if ( is_link( $path ) ) {
					$this->links[] = $sub;
				} elseif ( ! in_array( $sub, $this->skip, true ) && ! $this->dir( $path, $sub, $on_path ? array_slice( $after, 1 ) : array() ) ) {
					return false;
				}
				continue;
			}
			if ( ( $on_path && 1 === count( $after ) ) || ! is_file( $path ) ) {
				continue;
			}
			if ( ( $this->stop )() ) {
				return false;
			}
			( $this->visit )( $path, $sub );
			$this->cursor = $sub;
			++$this->files;
		}
		return true;
	}
}
