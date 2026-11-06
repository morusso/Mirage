<?php
/**
 * The base configuration for WordPress (backup copy)
 */

define( 'DB_NAME', 'shopnest_wp' );
define( 'DB_USER', 'shopnest' );
define( 'DB_PASSWORD', '{{ db_password }}' );
define( 'DB_HOST', '{{ db_host }}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         '{{ salt }}1' );
define( 'SECURE_AUTH_KEY',  '{{ salt }}2' );
define( 'LOGGED_IN_KEY',    '{{ salt }}3' );
define( 'NONCE_KEY',        '{{ salt }}4' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
