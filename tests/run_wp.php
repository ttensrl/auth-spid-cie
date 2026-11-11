<?php
/**
 * Tests for the parts that touch WordPress APIs, with in-memory stubs:  php tests/run_wp.php
 */
require __DIR__ . '/bootstrap.php';

const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS   = 3600;

$GLOBALS['opts']   = array();
$GLOBALS['trans']  = array();
$GLOBALS['redirect'] = null;
$GLOBALS['tmp']    = sys_get_temp_dir() . '/wpspid-test-' . bin2hex( random_bytes( 4 ) );
mkdir( $GLOBALS['tmp'], 0777, true );
// Mai nella cartella dati reale del plugin: i test usano una cartella temporanea.
define( 'WPSPID_PRIVATE_DIR', $GLOBALS['tmp'] . '/private' );
define( 'WP_CONTENT_DIR', $GLOBALS['tmp'] . '/content' );
mkdir( WP_CONTENT_DIR . '/upgrade', 0777, true );

function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function home_url( $p = '' ) { return 'https://sp.example.it' . $p; }
function get_transient( $k ) { return array_key_exists( $k, $GLOBALS['trans'] ) ? $GLOBALS['trans'][ $k ] : false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
function update_option( $k, $v ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function wp_upload_dir() { return array( 'basedir' => $GLOBALS['tmp'] ); }
function trailingslashit( $s ) { return rtrim( $s, '/' ) . '/'; }
function wp_mkdir_p( $d ) { return is_dir( $d ) || mkdir( $d, 0777, true ); }
function wp_parse_args( $a, $d ) { return array_merge( $d, (array) $a ); }
function get_bloginfo( $x ) { return 'Test Site'; }
function wp_redirect( $url ) { $GLOBALS['redirect'] = $url; }
function wp_parse_url( $u, $c = -1 ) { return parse_url( $u, $c ); }
function wp_remote_get( $u, $a = array() ) { return new WP_Error(); }
function is_wp_error( $x ) { return $x instanceof WP_Error; }
class WP_Error {}
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $s ) { return esc_html( $s ); }
function esc_url( $u ) { return esc_html( $u ); }
function esc_html__( $s, $d = '' ) { return $s; }
function __( $s, $d = '' ) { return $s; }
function add_query_arg( $args, $url = '' ) { return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $args, '', '&', PHP_QUERY_RFC3986 ); }
function wp_create_nonce( $a ) { return 'nonce_' . $a; }
function apply_filters( $tag, $value, ...$rest ) { return isset( $GLOBALS['filters'][ $tag ] ) ? $GLOBALS['filters'][ $tag ]( $value, ...$rest ) : $value; }
function wp_enqueue_style( $h ) { $GLOBALS['enqueued'][] = $h; }
function get_template_directory() { return $GLOBALS['tmp'] . '/theme'; }
function get_template_directory_uri() { return 'https://sp.example.it/wp-content/themes/wp-pa-theme'; }
define( 'WPSPID_PLUGIN_URL', 'https://sp.example.it/wp-content/plugins/auth-spid-cie/' );

use WpSpidCie\Cert\CertificateManager;
use WpSpidCie\Saml\AuthnRequestBuilder;
use WpSpidCie\Saml\Bindings;
use WpSpidCie\Idp\Registry;
use WpSpidCie\State\ReplayCache;
use WpSpidCie\State\RequestStore;
use WpSpidCie\Xml\SignatureVerifier;
use WpSpidCie\Xml\XmlSecurity;

$pass = 0; $fail = 0;
function ok( $c, $n ) { global $pass, $fail; if ( $c ) { $pass++; echo "  ok   $n\n"; } else { $fail++; echo "  FAIL $n\n"; } }
function throws( $n, callable $f ) { try { $f(); ok( false, "$n (nothing thrown)" ); } catch ( \Throwable $e ) { ok( true, "$n [" . $e->getMessage() . ']' ); } }

echo "== Certificates\n";
throws( 'AuthnRequest refused when SP has no key/cert', function () {
	AuthnRequestBuilder::build( 'https://idp.example.it', 'https://idp.example.it/sso', 2, 'spid', true );
} );
CertificateManager::generate( 'spid', array(
	'org_name' => 'Ente Test', 'common_name' => 'Ente Test', 'uri' => 'https://sp.example.it',
	'org_identifier' => 'PA:IT-c_h501', 'country' => 'IT', 'locality' => 'Roma', 'public' => true,
), 30 );
$pem_info = openssl_x509_parse( CertificateManager::get_certificate( 'spid' ) );
ok( isset( $pem_info['subject']['organizationIdentifier'] ) && 'PA:IT-c_h501' === $pem_info['subject']['organizationIdentifier'], 'certificate carries organizationIdentifier (AgID)' );
ok( false !== strpos( $pem_info['extensions']['certificatePolicies'], 'agidcert' ) && false !== strpos( $pem_info['extensions']['certificatePolicies'], 'spid-publicsector-SP' ), 'certificate carries agIDcert + spid-publicsector policies' );
throws( 'certificate generation refuses missing data', function () {
	CertificateManager::generate( 'cie', array( 'org_name' => 'X' ), 30 );
} );
$info = CertificateManager::info( 'spid' );
ok( $info && $info['days_left'] >= 29, 'CertificateManager::info reports validity' );
$paths = CertificateManager::get_paths( 'spid' );
ok( CertificateManager::exists( 'spid' ), 'certificate generated' );
ok( ( fileperms( $paths['key'] ) & 0777 ) === 0600, 'private key file mode is 0600' );
ok( strpos( file_get_contents( dirname( $paths['key'] ) . '/.htaccess' ), 'Require all denied' ) !== false, '.htaccess uses Apache 2.4 syntax' );
throws( 'import rejects key that does not match certificate', function () {
	$other = openssl_pkey_new( array( 'private_key_bits' => 2048 ) );
	openssl_pkey_export( $other, $pem );
	CertificateManager::import( 'cie', $pem, CertificateManager::get_certificate( 'spid' ) );
} );

echo "== AuthnRequest\n";
$cert = CertificateManager::get_certificate( 'spid' );
$req  = AuthnRequestBuilder::build( 'https://idp.example.it', 'https://idp.example.it/sso', 99, 'spid', true );
ok( 3 === $req['level'], 'level 99 clamped to 3' );
ok( strpos( $req['xml'], 'wpspid=metadata&amp;service=spid' ) !== false, 'entityID with & is escaped in the Issuer (regression)' );
$doc = XmlSecurity::load_xml( $req['xml'] );
ok( strpos( $req['xml'], 'SpidL3' ) !== false && strpos( $req['xml'], 'SpidL99' ) === false, 'class ref is SpidL3' );
$err = null;
try { SignatureVerifier::verify_element( $doc, $doc->documentElement, array( $cert ) ); } catch ( \Exception $e ) { $err = $e->getMessage(); }
ok( null === $err, 'embedded XML signature verifies with SP certificate' . ( $err ? " ($err)" : '' ) );
ok( 'https://idp.example.it' === $doc->documentElement->getAttribute( 'Destination' ), 'Destination = IdP entityID by default' );
$GLOBALS['opts']['wpspid_options'] = array( 'destination_mode' => 'sso_url' );
$req2 = AuthnRequestBuilder::build( 'https://idp.example.it', 'https://idp.example.it/sso', 2, 'spid', false );
$doc2 = XmlSecurity::load_xml( $req2['xml'] );
ok( 'https://idp.example.it/sso' === $doc2->documentElement->getAttribute( 'Destination' ), 'Destination = SSO URL when configured' );
ok( false === strpos( $req2['xml'], 'ds:Signature' ), 'no embedded signature for HTTP-Redirect' );
$GLOBALS['opts'] = array();

echo "== Redirect binding\n";
$url = Bindings::build_redirect_url( 'https://idp.example.it/sso', $req2['xml'], '', 'spid' );
$qs  = substr( $url, strpos( $url, '?' ) + 1 );
$pos = strrpos( $qs, '&Signature=' );
$signed = substr( $qs, 0, $pos );
$sig    = base64_decode( urldecode( substr( $qs, $pos + 11 ) ) );
$pub    = openssl_pkey_get_public( $cert );
ok( 1 === openssl_verify( $signed, $sig, $pub, OPENSSL_ALGO_SHA256 ), 'query-string signature verifies' );
ok( strpos( $signed, 'SigAlg=' ) !== false, 'SigAlg is part of the signed string' );

echo "== State\n";
RequestStore::set( 'wpspid_x', array( 'a' => 1 ) );
ok( array( 'a' => 1 ) === RequestStore::consume( 'wpspid_x' ), 'pending request consumed once' );
ok( false === RequestStore::consume( 'wpspid_x' ), 'second consume fails' );
ok( true === ReplayCache::mark( 'a:1', time() + 300 ), 'first assertion id accepted' );
ok( false === ReplayCache::mark( 'a:1', time() + 300 ), 'replayed assertion id refused' );

echo "== Registry (bundled snapshot, network stubbed off)\n";
$idps = Registry::get_instance()->get_idps();
ok( count( $idps ) >= 10, 'registry snapshot loaded (' . count( $idps ) . ' IdPs)' );
$first = $idps[0];
ok( isset( $first['sso'][0]['binding'], $first['sso'][0]['location'] ), 'SSO endpoints normalised to lowercase keys' );
ok( ! empty( $first['certs'] ), 'IdP signing certificates present' );

echo "== Metadata\n";
$GLOBALS['opts']['admin_email'] = 'admin@example.it';
$base = array(
	'entity_id' => 'https://sp.example.it', 'org_name' => 'Ente & Figli S.p.A.', 'org_display_name' => 'Ente', 'org_url' => 'https://www.example.it',
	'org_code' => 'c_h501', 'locality' => 'Roma', 'contact_email' => 'info@example.it', 'contact_phone' => '+390612345678',
	'cie_nace2' => '84.11', 'cie_municipality' => '058091', 'cie_province' => 'RM', 'cie_fiscal_code' => '01234567890',
	'fpa_id_codice' => '01234567890', 'fpa_denominazione' => 'Ente Srl', 'fpa_indirizzo' => 'Via Roma', 'fpa_numero_civico' => '1', 'fpa_cap' => '00100',
	'fpa_comune' => 'Roma', 'fpa_provincia' => 'RM', 'fpa_org_name' => 'Ente Srl', 'fpa_email' => 'f@example.it', 'fpa_phone' => '+390612345678',
);
foreach ( array( 'public' => 'IPACode', 'private' => 'VATNumber' ) as $sector => $code_type ) {
	$GLOBALS['opts']['wpspid_options'] = array_merge( $base, array( 'sp_type' => $sector, 'org_code_type' => $code_type, 'org_code' => 'public' === $sector ? 'c_h501' : '01234567890' ) );
	foreach ( array( 'spid', 'cie' ) as $svc ) {
		if ( ! CertificateManager::exists( $svc ) ) {
			CertificateManager::generate( $svc, array( 'org_name' => 'E', 'common_name' => 'E', 'uri' => 'https://sp.example.it', 'org_identifier' => 'PA:IT-x', 'country' => 'IT', 'locality' => 'Roma', 'public' => true ), 30 );
		}
		$md   = \WpSpidCie\Saml\MetadataBuilder::generate( $svc );
		$mdoc = null;
		try { $mdoc = XmlSecurity::load_xml( $md ); } catch ( \Exception $e ) { echo '    ' . $e->getMessage() . "\n"; }
		ok( null !== $mdoc, "$sector/$svc metadata is well-formed XML (name with &)" );
		$err = null;
		try { SignatureVerifier::verify_element( $mdoc, $mdoc->documentElement, array( CertificateManager::get_certificate( $svc ) ) ); } catch ( \Exception $e ) { $err = $e->getMessage(); }
		ok( null === $err, "$sector/$svc metadata signature verifies" . ( $err ? " ($err)" : '' ) );
		ok( false !== strpos( $md, 'Ente &amp; Figli' ), "$sector/$svc organisation name escaped" );
		if ( 'spid' === $svc ) {
			ok( 'public' === $sector ? false !== strpos( $md, 'spid:IPACode' ) && false !== strpos( $md, 'spid:Public' ) : 1 === preg_match( '#spid:VATNumber[^>]*>IT01234567890<#', $md ) && false !== strpos( $md, 'spid:Private' ) && false !== strpos( $md, 'fpa:CessionarioCommittente' ) && false !== strpos( $md, 'contactType="billing"' ), "$sector/spid ContactPerson extensions" );
		} else {
			ok( false !== strpos( $md, 'public' === $sector ? 'cie:Public' : 'cie:NACE2Code' ), "$sector/cie ContactPerson extensions" );
		}
	}
}
$GLOBALS['opts'] = array();

echo "== Options (sanitize)\n";
use WpSpidCie\Settings\OptionsManager;
$san = OptionsManager::sanitize( array( '_form' => 1, 'entity_id' => 'http://insecure.example', 'cie_level' => 9, 'acs_index' => -3, 'sp_type' => 'private', 'org_code' => 'IT 0123-4567890!', 'fpa_provincia' => 'rm1', 'attributes' => array( 'name', 'bogus' ), 'test_idp_urls' => "https://localhost:8443/metadata.xml\nhttp://nope\nhttps://localhost:8443/metadata.xml" ) );
ok( '' === $san['entity_id'], 'non-https entityID rejected' );
ok( 3 === $san['cie_level'] && 0 === $san['acs_index'], 'levels clamped' );
ok( 'IT0123-4567890' === $san['org_code'] && 'RM' === $san['fpa_provincia'], 'codes sanitised' );
ok( in_array( 'fiscalNumber', $san['attributes'], true ) && in_array( 'name', $san['attributes'], true ) && ! in_array( 'bogus', $san['attributes'], true ), 'attributes whitelisted, fiscalNumber forced' );
ok( array( 'https://localhost:8443/metadata.xml' ) === $san['test_idp_urls'], 'test IdP URLs: https only, de-duplicated' );
ok( false === $san['enabled'] && false === $san['production'], 'unchecked checkboxes become false on form submit' );
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => true, 'org_name' => 'Keep me' );
$partial = OptionsManager::sanitize( array( 'cie_level' => 1 ) );
ok( true === $partial['enabled'] && 'Keep me' === $partial['org_name'], 'programmatic partial update keeps stored values' );
$GLOBALS['opts'] = array();
$miss = OptionsManager::missing_for_metadata( array(), 'spid' );
ok( in_array( 'entityID', $miss, true ) && in_array( 'IPA code', $miss, true ), 'missing_for_metadata lists what to fill' );
ok( array() === OptionsManager::missing_for_metadata( $base + array( 'sp_type' => 'public' ), 'spid' ), 'complete public data -> nothing missing' );

echo "== Test IdPs\n";
$GLOBALS['opts']['wpspid_options'] = array( 'production' => true, 'test_demo' => true, 'test_idp_urls' => array( 'https://localhost:8443/metadata.xml' ) );
ok( array() === \WpSpidCie\Idp\TestIdps::get_all(), 'no test IdP is ever offered in production' );
$GLOBALS['opts'] = array();


echo "== Requirements (OpenSSL probe)\n";
use WpSpidCie\Support\Requirements;
$base_subject = array( 'org_name' => 'Ente Test', 'common_name' => 'Ente Test', 'uri' => 'https://sp.example.it', 'org_identifier' => 'PA:IT-c_h501', 'country' => 'IT', 'locality' => 'Roma', 'public' => true );
ok( array() === Requirements::check(), 'this environment satisfies the requirements' );
$r = Requirements::probe( true );
ok( true === $r['ok'] && array() === $r['errors'], 'probe: a real key + CSR + certificate (SPID and CIE) can be generated' );
ok( ! empty( $r['openssl_version'] ), 'probe reports the OpenSSL version' );
ok( true === Requirements::cached()['ok'], 'successful probe is cached' );
$e = Requirements::check( array( 'extensions' => array( 'dom', 'libxml', 'mbstring' ) ) );
ok( 1 === count( $e ) && false !== strpos( $e[0], 'openssl' ), 'missing openssl extension is reported' );
$e = Requirements::check( array( 'functions' => array( 'openssl_pkey_new' ) ) );
ok( count( $e ) >= 1 && false !== strpos( implode( ' ', $e ), 'openssl_csr_new' ), 'disabled OpenSSL functions are reported by name' );
$p = Requirements::probe( true, array( 'tmp_writable' => false ) );
ok( false === $p['ok'] && false !== stripos( implode( ' ', $p['errors'] ), 'temporary folder' ), 'probe fails when the temp dir is not writable' );
ok( false === Requirements::cached()['ok'], 'failed probe is cached too (so the plugin stays blocked)' );
$p = Requirements::probe( true, array( 'functions' => array() ) );
ok( false === $p['ok'] && count( $p['errors'] ) >= 1, 'probe fails when OpenSSL functions are unavailable' );
Requirements::$env = array( 'functions' => array() );
throws( 'certificate generation is blocked when OpenSSL is unusable', function () use ( $base_subject ) {
	CertificateManager::generate( 'blocked', $base_subject, 30 );
} );
Requirements::$env = array();
ok( false === CertificateManager::exists( 'blocked' ), 'no key/cert files are created when generation is blocked' );
ok( true === Requirements::probe( true )['ok'], 'probe recovers once the environment is fine again' );

echo "== Storage inside the plugin folder\n";
ok( WPSPID_PLUGIN_DIR . 'data/' === CertificateManager::default_storage_dir(), 'default storage is the plugin data/ folder' );
$kf = CertificateManager::get_paths( 'spid' )['key'];
ok( '.key.php' === substr( $kf, -8 ), 'private key is stored as a .php file' );
ok( 0 === strpos( file_get_contents( $kf ), '<?php' ), 'key file starts with a PHP guard' );
$out = shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $kf ) . ' 2>&1' );
ok( '' === trim( (string) $out ), 'executing the key file prints nothing (a web server that runs PHP leaks nothing)' );
ok( false !== openssl_pkey_get_private( CertificateManager::get_private_key( 'spid' ) ), 'the guard is stripped when the key is read' );
$gi = file_get_contents( dirname( $kf ) . '/.gitignore' );
ok( false !== strpos( $gi, '*' ) && false !== strpos( $gi, '!.htaccess' ), 'data dir has a .gitignore that excludes everything else' );
ok( file_exists( dirname( $kf ) . '/index.php' ), 'data dir has an index.php' );
$kp = openssl_pkey_new( array( 'private_key_bits' => 2048 ) );
openssl_pkey_export( $kp, $imp_key );
$csr  = openssl_csr_new( array( 'commonName' => 'imp' ), $kp );
openssl_x509_export( openssl_csr_sign( $csr, null, $kp, 30 ), $imp_cert );
CertificateManager::import( 'imported', $imp_key, $imp_cert );
ok( 0 === strpos( file_get_contents( CertificateManager::get_paths( 'imported' )['key'] ), '<?php' ), 'imported keys get the guard too' );
ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'imported' ) ), 'imported key round-trips unchanged' );
// Migrazione dalla vecchia posizione (uploads, chiave in chiaro).
$legacy = $GLOBALS['tmp'] . '/legacy/';
mkdir( $legacy, 0777, true );
file_put_contents( $legacy . 'old-sp.key', $imp_key );
file_put_contents( $legacy . 'old-sp.crt', $imp_cert );
ok( true === CertificateManager::migrate_legacy( 'old', $legacy ), 'legacy key/cert are migrated' );
ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'old' ) ) && ! file_exists( $legacy . 'old-sp.key' ), 'migrated key is readable and the exposed legacy key is deleted' );
file_put_contents( $legacy . 'bad-sp.key', $imp_key );
openssl_pkey_export( openssl_pkey_new( array( 'private_key_bits' => 2048 ) ), $other_key );
file_put_contents( $legacy . 'bad-sp.crt', CertificateManager::get_certificate( 'spid' ) );
ok( false === CertificateManager::migrate_legacy( 'bad', $legacy ) && file_exists( $legacy . 'bad-sp.key' ) && ! CertificateManager::exists( 'bad' ), 'mismatched legacy pair is NOT migrated and left untouched' );

echo "== Data survives plugin updates\n";
use WpSpidCie\Support\DataPreserver;
$src = $GLOBALS['tmp'] . '/upd/data';
mkdir( $src . '/sub', 0777, true );
file_put_contents( $src . '/spid-sp.key.php', "<?php exit; ?>\nSECRET" );
chmod( $src . '/spid-sp.key.php', 0600 );
file_put_contents( $src . '/.htaccess', 'deny' );
file_put_contents( $src . '/sub/registered-spid.xml', '<x/>' );
$bk = $GLOBALS['tmp'] . '/upd/backup';
ok( true === DataPreserver::backup( $src, $bk ), 'backup copies the data dir' );
DataPreserver::remove_dir( $src ); // quello che fa WordPress durante l'aggiornamento
ok( ! is_dir( $src ), 'WordPress update wipes the plugin data dir (simulated)' );
ok( true === DataPreserver::restore( $bk, $src ), 'restore brings the files back' );
ok( "<?php exit; ?>\nSECRET" === file_get_contents( $src . '/spid-sp.key.php' ) && '<x/>' === file_get_contents( $src . '/sub/registered-spid.xml' ) && 'deny' === file_get_contents( $src . '/.htaccess' ), 'restored files (including dotfiles and subfolders) are identical' );
ok( ( fileperms( $src . '/spid-sp.key.php' ) & 0777 ) === 0600, 'restored private key keeps mode 0600' );
ok( ! is_dir( $bk ), 'backup is removed after a verified restore' );
mkdir( $bk, 0777, true );
file_put_contents( $bk . '/spid-sp.key.php', 'X' );
ok( false === DataPreserver::restore( $bk, '/proc/forbidden/data' ) && is_dir( $bk ), 'failed restore keeps the backup' );
ok( false === DataPreserver::backup( $GLOBALS['tmp'] . '/does-not-exist', $GLOBALS['tmp'] . '/x' ), 'nothing to back up -> false, nothing created' );
$GLOBALS['opts']['wpspid_preserved_path'] = null;
DataPreserver::on_pre_install( true, array( 'type' => 'plugin', 'plugin' => 'another-plugin/another.php' ) );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'updates of other plugins are ignored' );

// Reinstallazione / upload con "sostituisci": WordPress NON passa la chiave 'plugin' agli hook.
// (Trovato con un vero `wp plugin install --force`, che aveva cancellato i dati.)
$inst = $GLOBALS['tmp'] . '/inst';
mkdir( $inst . '/auth-spid-cie', 0777, true );
file_put_contents( $inst . '/auth-spid-cie/auth-spid-cie.php', '<?php // Plugin Name: Auth SPID CIE' );
$data_old = $GLOBALS['tmp'] . '/inst-data';
mkdir( $data_old, 0777, true );
file_put_contents( $data_old . '/spid-sp.key.php', "<?php exit; ?>\nSECRET2" );
chmod( $data_old . '/spid-sp.key.php', 0600 );
DataPreserver::$test_dir    = $data_old;
DataPreserver::$test_folder = 'auth-spid-cie';
$GLOBALS['opts']['wpspid_preserved_path'] = null;
$install_extra = array( 'type' => 'plugin', 'action' => 'install' );
$sel = DataPreserver::on_source_selection( $inst . '/auth-spid-cie', '/x', null, $install_extra );
ok( $inst . '/auth-spid-cie' === $sel, 'source selection returns the source unchanged' );
ok( ! empty( $GLOBALS['opts']['wpspid_preserved_path'] ) && is_dir( $GLOBALS['opts']['wpspid_preserved_path'] ), 'reinstall (hook_extra without "plugin") triggers the backup' );
DataPreserver::remove_dir( $data_old );
$new_plugin = $GLOBALS['tmp'] . '/inst-newplugin';
mkdir( $new_plugin, 0777, true );
DataPreserver::on_post_install( true, $install_extra, array( 'destination' => $new_plugin ) );
ok( "<?php exit; ?>\nSECRET2" === @file_get_contents( $new_plugin . '/data/spid-sp.key.php' ), 'reinstall restores the data into the new plugin folder' );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'and clears the backup pointer' );
// negativi
$GLOBALS['opts']['wpspid_preserved_path'] = null;
mkdir( $data_old, 0777, true );
file_put_contents( $data_old . '/k', 'x' );
mkdir( $inst . '/another-plugin', 0777, true );
file_put_contents( $inst . '/another-plugin/another.php', '<?php' );
DataPreserver::on_source_selection( $inst . '/another-plugin', '/x', null, $install_extra );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'installing a different plugin is ignored' );
mkdir( $inst . '/no-main', 0777, true );
rename( $inst . '/no-main', $inst . '/auth-spid-cie-x' );
DataPreserver::on_source_selection( $inst . '/auth-spid-cie-x', '/x', null, $install_extra );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'a folder with another name is ignored' );
DataPreserver::on_source_selection( $inst . '/auth-spid-cie', '/x', null, array( 'type' => 'theme', 'action' => 'install' ) );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'themes are ignored' );
// Installazione fallita: la copia di sicurezza non deve restare orfana se la cartella dati e' ancora al suo posto.
// (Trovato in una prova vera: l'aggiornamento e' fallito prima di cancellare la cartella e la copia e' rimasta.)
$GLOBALS['opts']['wpspid_preserved_path'] = null;
mkdir( $data_old, 0777, true );
file_put_contents( $data_old . '/k.key.php', 'SECRET3' );
DataPreserver::on_source_selection( $inst . '/auth-spid-cie', '/x', null, $install_extra );
$stale = $GLOBALS['opts']['wpspid_preserved_path'];
ok( ! empty( $stale ) && is_dir( $stale ), 'backup made before the install' );
$err = new WP_Error();
ok( $err === DataPreserver::on_install_result( $err, $install_extra ), 'install result is passed through untouched' );
ok( empty( $GLOBALS['opts']['wpspid_preserved_path'] ) && ! is_dir( $stale ), 'failed install with the data folder still in place: the useless backup is removed' );
DataPreserver::on_source_selection( $inst . '/auth-spid-cie', '/x', null, $install_extra );
$kept = $GLOBALS['opts']['wpspid_preserved_path'];
DataPreserver::remove_dir( $data_old ); // l'aggiornamento ha gia' cancellato la cartella
DataPreserver::on_install_result( new WP_Error(), $install_extra );
ok( ! empty( $GLOBALS['opts']['wpspid_preserved_path'] ) && is_dir( $kept ), 'failed install after the data folder was wiped: the backup is KEPT' );
DataPreserver::remove_dir( $kept );
$GLOBALS['opts']['wpspid_preserved_path'] = null;
$ok_result = array( 'destination' => '/x' );
ok( $ok_result === DataPreserver::on_install_result( $ok_result, $install_extra ), 'a successful install is left alone (the restore happens in post_install)' );
DataPreserver::reset_state();
@mkdir( $data_old, 0777, true );
file_put_contents( $data_old . '/k', 'x' );
DataPreserver::$test_backup_root = '/proc/forbidden';
$res = DataPreserver::on_source_selection( $inst . '/auth-spid-cie', '/x', null, $install_extra );
ok( $res instanceof WP_Error && empty( $GLOBALS['opts']['wpspid_preserved_path'] ), 'if the backup cannot be made the installation is aborted (WP_Error)' );
DataPreserver::$test_backup_root = null;
DataPreserver::$test_dir         = null;
DataPreserver::$test_folder      = null;
$GLOBALS['opts'] = array();

echo "== Metadata snapshot (what was registered)\n";
use WpSpidCie\Saml\MetadataSnapshot;
use WpSpidCie\Saml\MetadataBuilder;
$GLOBALS['opts']['wpspid_options'] = array_merge( $base, array( 'sp_type' => 'public', 'org_code_type' => 'IPACode', 'org_code' => 'c_h501' ) );
$m1 = MetadataBuilder::generate( 'spid' );
$m2 = MetadataBuilder::generate( 'spid' );
ok( $m1 !== $m2, 'two generations differ byte by byte (random ID, new signature)' );
ok( MetadataSnapshot::fingerprint( $m1 ) === MetadataSnapshot::fingerprint( $m2 ), 'normalised fingerprint is stable across generations' );
ok( 'none' === MetadataSnapshot::status( 'spid', $m1 )['state'], 'no snapshot yet -> state none' );
MetadataSnapshot::save( 'spid', $m1, 'registrato su AgID 2026-11' );
$st = MetadataSnapshot::status( 'spid', $m2 );
ok( 'same' === $st['state'] && 'registrato su AgID 2026-11' === $st['note'], 'regenerated metadata equals the registered one' );
ok( $m1 === file_get_contents( CertificateManager::get_storage_dir() . 'registered-spid.xml' ), 'registered XML is stored in the data folder' );
ok( 'none' === MetadataSnapshot::status( 'cie', MetadataBuilder::generate( 'cie' ) )['state'], 'snapshot is per service (cie still none)' );
$GLOBALS['opts']['wpspid_options']['org_name'] = 'Altro Ente Srl';
ok( 'changed' === MetadataSnapshot::status( 'spid', MetadataBuilder::generate( 'spid' ) )['state'], 'a changed organisation name is detected as a difference' );
$GLOBALS['opts']['wpspid_options'] = array_merge( $base, array( 'sp_type' => 'public', 'org_code_type' => 'IPACode', 'org_code' => 'c_h501', 'contact_email' => 'altra@example.it' ) );
ok( 'changed' === MetadataSnapshot::status( 'spid', MetadataBuilder::generate( 'spid' ) )['state'], 'a changed contact is detected too' );
throws( 'snapshot refuses something that is not metadata XML', function () {
	MetadataSnapshot::save( 'spid', '<not-metadata/>', '' );
} );
throws( 'snapshot refuses malformed XML', function () {
	MetadataSnapshot::save( 'spid', '<<<', '' );
} );
$GLOBALS['opts'] = array();


echo "== UI: pulsanti SPID/CIE e scelta dell'IdP\n";
use WpSpidCie\Ui\Buttons;
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => 1, 'spid_enabled' => 1, 'cie_enabled' => 1, 'cie_level' => 2, 'test_demo' => 0 );
$n_spid = count( \WpSpidCie\Idp\IdpRepository::get_spid_idps() );
$h = Buttons::spid_button();
ok( false !== strpos( $h, 'Log in with SPID' ), 'SPID button says "Log in with SPID"' );
ok( $n_spid === substr_count( $h, '<li' ), "all $n_spid SPID identity providers are listed" );
ok( false !== strpos( $h, 'wpspid=login' ) && false !== strpos( $h, 'level=2' ) && false !== strpos( $h, rawurlencode( 'https://posteid.poste.it' ) ), 'each IdP links to the login route with level 2 and its (encoded) entityID' );
ok( false !== strpos( $h, '<details' ) && false === strpos( $h, '<details open' ), 'list is collapsed by default (native details/summary, no JavaScript)' );
foreach ( array( 'https://www.spid.gov.it"', 'https://www.spid.gov.it/richiedi-spid', 'https://www.spid.gov.it/serve-aiuto' ) as $link ) {
	ok( false !== strpos( $h, $link ), "help link present: $link" );
}
ok( 0 === preg_match( '#<a [^>]*>\s*https?://#', $h ), 'an IdP whose registry display name is a URL is listed by its proper name' );
$firsts = array();
for ( $i = 0; $i < 40; $i++ ) { preg_match( '#<li[^>]*><a[^>]*>([^<]+)#', Buttons::spid_button(), $m ); $firsts[ $m[1] ] = 1; }
ok( count( $firsts ) >= 2, 'IdP order is random (AgID guidelines): ' . count( $firsts ) . ' different first entries in 40 renders' );
ok( false !== strpos( Buttons::spid_button( array( 'open' => true ) ), '<details open' ), 'the list can be rendered open (dedicated login page)' );
ok( false !== strpos( Buttons::spid_button( array( 'return' => 'https://sp.example.it/area/' ) ), 'returnTo=' . rawurlencode( 'https://sp.example.it/area/' ) ), 'returnTo is carried over' );
$c = Buttons::cie_button();
ok( false !== strpos( $c, 'Log in with CIE' ) && false !== strpos( $c, 'aria-disabled="true"' ) && false === strpos( $c, 'href=' ), 'CIE button is disabled (no link) when the CIE IdP has no certificates yet' );
set_transient( 'wpspid_cie_test', array( 'entity_id' => 'https://cie.example/idp', 'name' => 'CIE (test)', 'display_name' => 'CIE', 'logo' => '', 'type' => 'cie', 'certs' => array( 'CERT' ), 'sso' => array( array( 'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'location' => 'https://cie.example/sso' ) ), 'slo' => array() ) );
$c = Buttons::cie_button();
ok( false !== strpos( $c, 'Log in with CIE' ) && false !== strpos( $c, 'level=2' ) && false !== strpos( $c, rawurlencode( 'https://cie.example/idp' ) ) && false === strpos( $c, 'aria-disabled' ), 'CIE button links to the login route with the configured level once the IdP is usable' );
ok( '' === Buttons::logo( 'cie' ), 'no CIE logo is bundled (cie-graphics has no declared licence)' );
ok( false !== strpos( Buttons::logo( 'spid' ), 'assets/img/' ), 'the SPID logo (CC0) is bundled with the plugin' );
$GLOBALS['filters']['wpspid_logo_url'] = function ( $url, $service ) { return 'cie' === $service ? 'https://theme.example/cie.svg' : $url; };
ok( false !== strpos( Buttons::cie_button(), 'https://theme.example/cie.svg' ), 'the theme can supply the CIE logo through a filter' );
$GLOBALS['filters'] = array();
$u = Buttons::user_box( array( 'name' => '<script>alert(1)</script>', 'familyName' => 'Rossi' ), 'https://sp.example.it/?wpspid=slo&a=b' );
ok( false === strpos( $u, '<script>' ) && false !== strpos( $u, '&lt;script&gt;' ), 'user name is escaped (no markup injection from SAML attributes)' );
ok( false !== strpos( $u, 'wpspid=slo&amp;a=b' ), 'logout link is escaped' );
ok( '' === Buttons::user_box( array(), 'https://sp.example.it/?wpspid=slo' ), 'no attributes -> no "logged in" box' );
$GLOBALS['opts']['wpspid_options']['enabled'] = 0;
ok( '' === Buttons::spid_button() && '' === Buttons::cie_button() && '' === Buttons::page(), 'nothing is rendered while the plugin is disabled' );
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => 1, 'spid_enabled' => 0, 'cie_enabled' => 1 );
ok( '' === Buttons::spid_button() && '' !== Buttons::cie_button(), 'SPID can be switched off independently of CIE' );
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => 1, 'spid_enabled' => 1, 'cie_enabled' => 1, 'test_demo' => 0 );
$pg = Buttons::page();
ok( false !== strpos( $pg, '<h1' ) && false !== strpos( $pg, '<details open' ) && false !== strpos( $pg, 'Log in with CIE' ), 'login page: title, open SPID list and CIE button' );
ok( in_array( 'wpspid-ui', $GLOBALS['enqueued'], true ), 'the stylesheet is enqueued only when something is rendered' );
$GLOBALS['opts'] = array();


echo "== Integrazione con il tema (filtro dci_area_personale, logo CIE)\n";
use WpSpidCie\Integrations\Theme as ThemeIntegration;
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => 0 );
$area = array( 'label' => 'Area personale', 'url' => 'https://sp.example.it/wp-login.php' );
ok( $area === ThemeIntegration::area_personale( $area ), 'plugin disabled: the theme keeps its own Area personale link' );
$GLOBALS['opts']['wpspid_options'] = array( 'enabled' => 1 );
$a2 = ThemeIntegration::area_personale( $area );
ok( 'https://sp.example.it/?wpspid=choose' === $a2['url'] && 'Area personale' === $a2['label'], 'enabled: Area personale points to the SPID/CIE login page, label unchanged when logged out' );
ok( 'Mario Rossi' === ThemeIntegration::label( array( 'name' => 'Mario', 'familyName' => 'Rossi' ), 'Area personale' ), 'logged in: the label becomes the citizen\'s name' );
ok( 'Area personale' === ThemeIntegration::label( array(), 'Area personale' ) && 'Area personale' === ThemeIntegration::label( array( 'fiscalNumber' => 'X' ), 'Area personale' ), 'no name attribute: label unchanged' );
ok( 'https://x/y.svg' === ThemeIntegration::logo( 'https://x/y.svg', 'spid' ), 'only the CIE logo is supplied, the others are untouched' );
ok( '' === ThemeIntegration::logo( '', 'cie' ), 'no CIE logo when the theme does not ship one' );
mkdir( get_template_directory() . '/assets/images/identity', 0777, true );
file_put_contents( get_template_directory() . '/assets/images/identity/cie-bianco.svg', '<svg/>' );
ok( 'https://sp.example.it/wp-content/themes/wp-pa-theme/assets/images/identity/cie-bianco.svg' === ThemeIntegration::logo( '', 'cie' ), 'the CIE logo of the theme is used when present' );
ok( 'https://own.example/cie.svg' === ThemeIntegration::logo( 'https://own.example/cie.svg', 'cie' ), 'a logo set elsewhere is never overridden' );
$GLOBALS['opts'] = array();

echo "\n$pass passed, $fail failed\n";
exec( 'rm -rf ' . escapeshellarg( $GLOBALS['tmp'] ) );
exit( $fail ? 1 : 0 );
