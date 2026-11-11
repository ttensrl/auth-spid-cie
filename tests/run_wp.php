<?php
/**
 * Tests for the parts that touch WordPress APIs, with in-memory stubs:  php tests/run_wp.php
 */
require __DIR__ . '/bootstrap.php';
ob_start(); // l'output resta in buffer: headers_sent() e' falso e i cookie di sessione si possono impostare anche da CLI.

const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS   = 3600;

$GLOBALS['opts']   = array();
$GLOBALS['trans']  = array();
$GLOBALS['redirect'] = null;
$GLOBALS['tmp']    = sys_get_temp_dir() . '/wpspid-test-' . bin2hex( random_bytes( 4 ) );
mkdir( $GLOBALS['tmp'], 0777, true );
// Mai la cartella data/ reale del plugin: la migrazione cerca nelle cartelle temporanee dei test.
$GLOBALS['mig_data']   = $GLOBALS['tmp'] . '/old-data/';
$GLOBALS['mig_legacy'] = $GLOBALS['tmp'] . '/old-uploads/';
$GLOBALS['filters']['wpspid_migration_dirs'] = function () { return array( 'data' => $GLOBALS['mig_data'], 'legacy' => $GLOBALS['mig_legacy'] ); };

function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function home_url( $p = '' ) { return 'https://sp.example.it' . $p; }
function get_transient( $k ) { return array_key_exists( $k, $GLOBALS['trans'] ) ? $GLOBALS['trans'][ $k ] : false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
$GLOBALS['site_opts'] = array();
function get_site_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['site_opts'] ) ? $GLOBALS['site_opts'][ $k ] : $d; }
function update_site_option( $k, $v ) { $GLOBALS['site_opts'][ $k ] = $v; return true; }
function delete_site_option( $k ) { unset( $GLOBALS['site_opts'][ $k ] ); return true; }
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
ok( CertificateManager::exists( 'spid' ), 'certificate generated' );
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

echo "== Storage nel database (niente file)\n";
use WpSpidCie\Cert\KeyVault;
use WpSpidCie\Cert\Migrator;
use WpSpidCie\Cert\Storage;
use WpSpidCie\Saml\MetadataSnapshot as Snap;
ok( isset( $GLOBALS['site_opts']['wpspid_cert_spid'] ) && ! isset( $GLOBALS['opts']['wpspid_cert_spid'] ), 'the certificate is stored with the (network) site option API, never in a regular autoloaded option' );
$rec = $GLOBALS['site_opts']['wpspid_cert_spid'];
ok( 0 === strpos( $rec['key'], 'wpspid:1:plain:' ) && false !== strpos( $rec['key'], 'PRIVATE KEY' ), 'without WPSPID_SECRET the key blob is marked "plain", version 1' );
ok( KeyVault::S_PLAIN === CertificateManager::key_state( 'spid' )['status'] && false !== openssl_pkey_get_private( CertificateManager::get_private_key( 'spid' ) ), 'plain key: state plain, readable' );
ok( ! is_dir( WPSPID_PLUGIN_DIR . 'data/' ) || array() === array_diff( scandir( WPSPID_PLUGIN_DIR . 'data/' ), array( '.', '..', '.gitignore', '.htaccess', 'index.php' ) ), 'generating a certificate writes nothing into the plugin folder' );
$kp = openssl_pkey_new( array( 'private_key_bits' => 2048 ) );
openssl_pkey_export( $kp, $imp_key );
$csr  = openssl_csr_new( array( 'commonName' => 'imp' ), $kp );
openssl_x509_export( openssl_csr_sign( $csr, null, $kp, 30 ), $imp_cert );
CertificateManager::import( 'imported', $imp_key, $imp_cert );
ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'imported' ) ) && trim( $imp_cert ) === trim( CertificateManager::get_certificate( 'imported' ) ), 'imported key and certificate round-trip unchanged' );
ok( Storage::get( 'cert_a/../b' ) === null && isset( $GLOBALS['site_opts'] ) , 'storage names are sanitised' );

echo "== Cifratura facoltativa (libsodium, WPSPID_SECRET)\n";
if ( ! KeyVault::sodium_available() ) {
	echo "  SKIP sodium not available in this PHP build\n";
} else {
	KeyVault::$test_secret = 'segreto-di-prova-' . str_repeat( 'x', 20 );
	$blob = KeyVault::seal( $imp_key );
	ok( 0 === strpos( $blob, 'wpspid:1:enc:' ) && false === strpos( $blob, 'PRIVATE KEY' ), 'with the constant the blob is marked "enc" v1 and holds no PEM text' );
	ok( 1 === preg_match( '/^wpspid:1:enc:[a-f0-9]{16}:[A-Za-z0-9+\/=]+$/', $blob ), 'blob = marker + 8-byte key fingerprint + base64(nonce.ciphertext)' );
	ok( KeyVault::seal( $imp_key ) !== $blob, 'a fresh random nonce is used every time' );
	$o = KeyVault::open( $blob );
	ok( KeyVault::S_OK === $o['status'] && $imp_key === $o['key'], 'round trip: the same constant decrypts to the exact original key' );
	CertificateManager::import( 'enc', $imp_key, $imp_cert );
	ok( 0 === strpos( $GLOBALS['site_opts']['wpspid_cert_enc']['key'], 'wpspid:1:enc:' ) && trim( $imp_key ) === trim( CertificateManager::get_private_key( 'enc' ) ), 'import with the constant stores the key encrypted and reads it back' );
	ok( KeyVault::S_OK === CertificateManager::key_state( 'enc' )['status'], 'state ok for an encrypted, readable key' );
	// Costante cambiata.
	KeyVault::$test_secret = 'un-altro-segreto-completamente-diverso';
	$o = KeyVault::open( $blob );
	ok( KeyVault::S_WRONG_SECRET === $o['status'] && false === $o['key'], 'a different constant is recognised (wrong_secret), no key returned' );
	ok( false === CertificateManager::get_private_key( 'enc' ) && false !== CertificateManager::get_certificate( 'enc' ), 'unreadable key: get_private_key() is false, the public certificate is still there' );
	throws( 'signing refused with an explicit reason when the constant changed', function () { CertificateManager::private_key_or_fail( 'enc' ); } );
	// Costante assente.
	KeyVault::$test_secret = '';
	ok( KeyVault::S_NO_SECRET === KeyVault::open( $blob )['status'] && false === CertificateManager::get_private_key( 'enc' ), 'constant missing: no_secret, no key returned' );
	ok( false !== strpos( KeyVault::message( KeyVault::S_NO_SECRET ), 'WPSPID_SECRET' ) && false !== strpos( KeyVault::message( KeyVault::S_NO_SECRET ), 'registered again' ), 'the message tells to restore the constant or regenerate and re-register' );
	// Dato alterato.
	KeyVault::$test_secret = 'segreto-di-prova-' . str_repeat( 'x', 20 );
	$tampered = substr( $blob, 0, -6 ) . ( 'AAAAAA' === substr( $blob, -6 ) ? 'BBBBBB' : 'AAAAAA' );
	ok( KeyVault::S_CORRUPT === KeyVault::open( $tampered )['status'], 'altered ciphertext is detected (corrupt), never returned as a key' );
	ok( KeyVault::S_CORRUPT === KeyVault::open( 'wpspid:9:whatever' )['status'] && KeyVault::S_CORRUPT === KeyVault::open( '-----BEGIN PRIVATE KEY-----' )['status'], 'unknown format/version is corrupt' );
	// Chiave in chiaro e costante definita dopo.
	$o = KeyVault::open( 'wpspid:1:plain:' . $imp_key );
	ok( KeyVault::S_PLAIN_PENDING === $o['status'] && $imp_key === $o['key'], 'plain key + constant defined later: readable, flagged plain_pending' );
	CertificateManager::reseal( 'imported' );
	ok( 0 === strpos( $GLOBALS['site_opts']['wpspid_cert_imported']['key'], 'wpspid:1:enc:' ) && KeyVault::S_OK === CertificateManager::key_state( 'imported' )['status'] && trim( $imp_key ) === trim( CertificateManager::get_private_key( 'imported' ) ), 'reseal() encrypts a plain key in place' );
	// Costante tolta dopo la cifratura.
	KeyVault::$test_secret = null;
	ok( KeyVault::S_NO_SECRET === CertificateManager::key_state( 'imported' )['status'], 'constant removed after encrypting: reported, key not guessed' );
	// Sodium mancante.
	KeyVault::$test_secret    = 'segreto-di-prova-' . str_repeat( 'x', 20 );
	KeyVault::$test_no_sodium = true;
	ok( KeyVault::S_NO_SODIUM === KeyVault::open( $blob )['status'] && KeyVault::S_NO_SODIUM === KeyVault::open( 'wpspid:1:plain:' . $imp_key )['status'], 'constant defined but libsodium missing: blocked with its own status' );
	throws( 'saving is refused when the constant is defined and libsodium is missing', function () use ( $imp_key, $imp_cert ) { CertificateManager::import( 'nosodium', $imp_key, $imp_cert ); } );
	ok( false === CertificateManager::exists( 'nosodium' ), 'a refused save leaves nothing behind' );
	KeyVault::$test_no_sodium = false;
	KeyVault::$test_secret    = null;
	CertificateManager::delete( 'enc' );
	CertificateManager::delete( 'imported' );
}

echo "== Migrazione dai file (data/ e uploads) al database\n";
$saved_site_opts = $GLOBALS['site_opts']; // I test seguenti usano i certificati spid/cie creati prima: si ripristinano alla fine.
CertificateManager::delete( 'cie' );
function mk_old_data( $dir, $key, $cert, $with_snapshot = true ) {
	mkdir( $dir, 0777, true );
	file_put_contents( $dir . 'spid-sp.key.php', "<?php exit; ?>\n" . $key );
	file_put_contents( $dir . 'spid-sp.crt', $cert );
	foreach ( array( '.htaccess' => 'Require all denied', 'index.php' => '<?php // Silence is golden.', '.gitignore' => "*\n" ) as $n => $c ) { file_put_contents( $dir . $n, $c ); }
	if ( $with_snapshot ) {
		file_put_contents( $dir . 'registered-spid.xml', '<EntityDescriptor entityID="x"/>' );
		file_put_contents( $dir . 'registered-spid.json', json_encode( array( 'sha256' => str_repeat( 'a', 64 ), 'saved_at' => '2026-01-01T00:00:00+00:00', 'note' => 'n', 'entity_id' => 'x' ) ) );
	}
}
CertificateManager::delete( 'spid' );
Snap::delete( 'spid' );
Migrator::reset();
ok( array() === Migrator::run()['migrated'], 'nothing to migrate when the old folders do not exist' );
mk_old_data( $GLOBALS['mig_data'], $imp_key, $imp_cert );
Migrator::reset();
$res = Migrator::run();
ok( in_array( 'spid', $res['migrated'], true ) && in_array( 'registered-spid', $res['migrated'], true ) && array() === $res['issues'], 'key, certificate and registered metadata are migrated without issues' );
ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'spid' ) ) && trim( $imp_cert ) === trim( CertificateManager::get_certificate( 'spid' ) ), 'the old pair is now in the database, identical' );
$sn = Snap::get( 'spid' );
ok( $sn && '<EntityDescriptor entityID="x"/>' === $sn['xml'] && 'n' === $sn['note'], 'the registered metadata is in the database, identical' );
ok( ! is_dir( $GLOBALS['mig_data'] ), 'only AFTER the verification the old files are deleted, protection files and the empty folder included' );
Migrator::reset();
ok( array() === Migrator::run()['migrated'] && null === Storage::get( 'migration_issues' ), 'running again is a no-op (idempotent)' );

// Vecchia cartella uploads (chiave in chiaro).
CertificateManager::delete( 'spid' );
mkdir( $GLOBALS['mig_legacy'], 0777, true );
file_put_contents( $GLOBALS['mig_legacy'] . 'cie-sp.key', $imp_key );
file_put_contents( $GLOBALS['mig_legacy'] . 'cie-sp.crt', $imp_cert );
Migrator::reset();
$res = Migrator::run();
ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'cie' ) ) && ! file_exists( $GLOBALS['mig_legacy'] . 'cie-sp.key' ) && ! is_dir( $GLOBALS['mig_legacy'] ), 'legacy uploads folder: migrated, exposed plain key deleted, folder removed' );
CertificateManager::delete( 'cie' );

// Verifica che fallisce -> non si cancella niente.
openssl_pkey_export( openssl_pkey_new( array( 'private_key_bits' => 2048 ) ), $other_key );
mk_old_data( $GLOBALS['mig_data'], $other_key, $imp_cert ); // chiave e certificato non corrispondono
Migrator::reset();
$res = Migrator::run();
ok( ! in_array( 'spid', $res['migrated'], true ) && count( $res['issues'] ) >= 1 && false === CertificateManager::exists( 'spid' ), 'mismatched pair: not migrated, an issue is recorded' );
ok( is_file( $GLOBALS['mig_data'] . 'spid-sp.key.php' ) && is_file( $GLOBALS['mig_data'] . 'spid-sp.crt' ) && is_file( $GLOBALS['mig_data'] . '.htaccess' ), 'mismatched pair: every old file is left in place' );
ok( ! empty( Storage::get( 'migration_issues' ) ), 'the issue is persisted for the admin notice' );
exec( 'rm -rf ' . escapeshellarg( $GLOBALS['mig_data'] ) );

// Salvataggio che non torna: simulato con una costante definita ma senza sodium -> store() rifiuta.
if ( KeyVault::sodium_available() ) {
	mk_old_data( $GLOBALS['mig_data'], $imp_key, $imp_cert );
	KeyVault::$test_secret = 'segreto-di-prova-' . str_repeat( 'x', 20 );
	KeyVault::$test_no_sodium = true;
	Migrator::reset();
	$res = Migrator::run();
	ok( ! in_array( 'spid', $res['migrated'], true ) && is_file( $GLOBALS['mig_data'] . 'spid-sp.key.php' ) && ! CertificateManager::exists( 'spid' ), 'if saving to the database fails nothing is deleted and nothing is half-written' );
	KeyVault::$test_no_sodium = false;
	Migrator::reset();
	$res = Migrator::run();
	ok( in_array( 'spid', $res['migrated'], true ) && 0 === strpos( $GLOBALS['site_opts']['wpspid_cert_spid']['key'], 'wpspid:1:enc:' ) && ! is_dir( $GLOBALS['mig_data'] ), 'with the constant defined the migration stores the key encrypted' );
	ok( trim( $imp_key ) === trim( CertificateManager::get_private_key( 'spid' ) ), 'and it reads back correctly' );
	KeyVault::$test_secret = null;
	CertificateManager::delete( 'spid' );
	Snap::delete( 'spid' );
}

// Il database ha gia' un certificato diverso: i file vecchi non si toccano.
$ok_k   = openssl_pkey_get_private( $other_key );
$ok_csr = openssl_csr_new( array( 'commonName' => 'other' ), $ok_k );
openssl_x509_export( openssl_csr_sign( $ok_csr, null, $ok_k, 30 ), $other_cert );
CertificateManager::import( 'spid', $other_key, $other_cert );
mk_old_data( $GLOBALS['mig_data'], $imp_key, $imp_cert, false );
Migrator::reset();
$res = Migrator::run();
ok( ! in_array( 'spid', $res['migrated'], true ) && is_file( $GLOBALS['mig_data'] . 'spid-sp.key.php' ) && count( $res['issues'] ) >= 1, 'the database holds another certificate: old files are NOT deleted, conflict reported' );
exec( 'rm -rf ' . escapeshellarg( $GLOBALS['mig_data'] ) );
CertificateManager::delete( 'spid' );
Migrator::reset();
Migrator::run();
ok( array() === Migrator::issues(), 'issues are cleared once a run finds nothing wrong' );
CertificateManager::delete( 'imported' );

echo "== Disinstallazione\n";
use WpSpidCie\Support\Uninstaller;
$GLOBALS['wpdb'] = new class { public $options = 'wp_options'; public $queries = array(); public function query( $q ) { $this->queries[] = $q; return 1; } };
function delete_option_t( $k ) {}
$GLOBALS['opts']['wpspid_options'] = array( 'org_name' => 'X' );
CertificateManager::import( 'spid', $imp_key, $imp_cert );
Snap::store_raw( 'spid', '<EntityDescriptor/>', array( 'sha256' => str_repeat( 'b', 64 ) ) );
Uninstaller::run();
ok( ! empty( $GLOBALS['site_opts']['wpspid_cert_spid'] ) && null !== Snap::get( 'spid' ) && ! empty( $GLOBALS['opts']['wpspid_options'] ), 'default: certificate, key, registered metadata and organization settings are KEPT' );
ok( 1 === count( $GLOBALS['wpdb']->queries ) && false !== strpos( $GLOBALS['wpdb']->queries[0], 'transient' ) && false !== strpos( $GLOBALS['wpdb']->queries[0], 'wpspid' ), 'default: temporary data (sessions, pending requests, caches) is deleted' );
define( 'WPSPID_REMOVE_DATA_ON_UNINSTALL', true );
Uninstaller::run();
ok( ! isset( $GLOBALS['site_opts']['wpspid_cert_spid'] ) && null === Snap::get( 'spid' ) && ! isset( $GLOBALS['opts']['wpspid_options'] ), 'WPSPID_REMOVE_DATA_ON_UNINSTALL=true: everything is deleted' );
CertificateManager::delete( 'spid' );
$GLOBALS['site_opts'] = $saved_site_opts;
$GLOBALS['opts']['wpspid_options'] = array();

echo "== Sessione (cookie + transient, senza sessioni PHP)\n";
use WpSpidCie\Auth\SessionGate;
if ( ! defined( 'YEAR_IN_SECONDS' ) ) { define( 'YEAR_IN_SECONDS', 31536000 ); }
if ( ! function_exists( 'is_ssl' ) ) { function is_ssl() { return false; } }
if ( ! function_exists( 'sanitize_text_field' ) ) { function sanitize_text_field( $s ) { return trim( strip_tags( $s ) ); } }
if ( ! function_exists( 'wp_unslash' ) ) { function wp_unslash( $v ) { return is_string( $v ) ? stripslashes( $v ) : $v; } }
$GLOBALS['trans'] = array();
unset( $_COOKIE[ SessionGate::COOKIE ] );
SessionGate::reset_cache();
ok( false === SessionGate::is_authenticated() && array() === SessionGate::attributes(), 'anonymous visitor: not authenticated, no cookie needed' );
SessionGate::login( array( 'fiscalNumber' => 'TINIT-RSSMRA80A01H501U', 'name' => 'Mario' ), array( 'idp' => 'https://idp.example', 'session_index' => 's1' ) );
$sid = $_COOKIE[ SessionGate::COOKIE ];
ok( 1 === preg_match( '/^[a-f0-9]{64}$/', $sid ), 'the cookie carries a random 256-bit identifier' );
ok( true === SessionGate::is_authenticated() && 'Mario' === SessionGate::attributes()['name'] && 's1' === SessionGate::meta()['session_index'], 'attributes and meta available after login' );
ok( 1 === count( $GLOBALS['trans'] ) && false === strpos( (string) key( $GLOBALS['trans'] ), $sid ), 'server side the data sits under a hash, never under the cookie value' );
SessionGate::reset_cache();
ok( true === SessionGate::is_authenticated(), 'a new request with the same cookie finds the session' );
$_COOKIE[ SessionGate::COOKIE ] = str_repeat( 'a', 64 );
SessionGate::reset_cache();
ok( false === SessionGate::is_authenticated(), 'an unknown identifier is not authenticated' );
$_COOKIE[ SessionGate::COOKIE ] = '../' . $sid;
SessionGate::reset_cache();
ok( false === SessionGate::is_authenticated(), 'a malformed cookie is ignored' );
$_COOKIE[ SessionGate::COOKIE ] = $sid;
SessionGate::reset_cache();
$k = key( $GLOBALS['trans'] ); $d = $GLOBALS['trans'][ $k ]; $d['meta']['time'] = time() - 3 * HOUR_IN_SECONDS; $GLOBALS['trans'][ $k ] = $d;
ok( false === SessionGate::is_authenticated() && array() === $GLOBALS['trans'], 'expired session: refused and deleted server side' );
SessionGate::login( array( 'name' => 'A' ) );
$first = $_COOKIE[ SessionGate::COOKIE ];
SessionGate::login( array( 'name' => 'B' ) );
ok( $first !== $_COOKIE[ SessionGate::COOKIE ] && 1 === count( $GLOBALS['trans'] ), 'a new login issues a new identifier and drops the old session (no fixation)' );
SessionGate::logout();
SessionGate::reset_cache();
ok( false === SessionGate::is_authenticated() && array() === $GLOBALS['trans'] && ! isset( $_COOKIE[ SessionGate::COOKIE ] ), 'logout removes the session on the server and the cookie' );

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
ok( $m1 === MetadataSnapshot::get( 'spid' )['xml'] && isset( $GLOBALS['site_opts']['wpspid_registered_spid'] ), 'registered XML is stored in the database' );
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
ok( 0 === preg_match( '#<a [^>]*>\s*https?://#', $h ) && 0 === preg_match( '#alt="https?://#', $h ), 'an IdP whose registry display name is a URL is listed by its proper name' );
ok( false === strpos( $h, 'jsdelivr' ) && false !== strpos( $h, 'assets/img/idp/spid-idp-posteid.svg' ), 'IdP logos come from the plugin, never from an external CDN' );
$firsts = array();
for ( $i = 0; $i < 40; $i++ ) { preg_match( '#<li[^>]*><a[^>]*>(?:<img[^>]*alt="([^"]+)"|([^<]+))#', Buttons::spid_button(), $m ); $firsts[ '' !== $m[1] ? $m[1] : $m[2] ] = 1; }
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
