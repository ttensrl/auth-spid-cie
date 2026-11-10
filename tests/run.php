<?php
/**
 * Dependency-free test runner:  php tests/run.php
 * Covers XML signing/verification and SAML Response validation (positive + attack cases).
 */
require __DIR__ . '/bootstrap.php';

use WpSpidCie\Saml\ResponseValidator;
use WpSpidCie\Saml\ValidationException;
use WpSpidCie\Xml\Signer;
use WpSpidCie\Xml\SignatureVerifier;
use WpSpidCie\Xml\XmlSecurity;

$GLOBALS['pass'] = 0;
$GLOBALS['fail'] = 0;

function ok( $cond, $name ) {
	if ( $cond ) {
		$GLOBALS['pass']++;
		echo "  ok   $name\n";
	} else {
		$GLOBALS['fail']++;
		echo "  FAIL $name\n";
	}
}

/** Expect validate() to throw ValidationException (optionally with a reason). */
function rejects( $name, callable $fn, $reason = null ) {
	try {
		$fn();
		ok( false, $name . ' (nothing thrown)' );
	} catch ( ValidationException $e ) {
		ok( null === $reason || $e->reason === $reason, $name . ' [' . $e->reason . ']' . ( null !== $reason && $e->reason !== $reason ? " expected $reason" : '' ) );
	} catch ( \Throwable $e ) {
		ok( false, $name . ' (wrong exception: ' . get_class( $e ) . ': ' . $e->getMessage() . ')' );
	}
}

function make_keypair() {
	$cfg = array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'sha256' );
	$key = openssl_pkey_new( $cfg );
	$csr = openssl_csr_new( array( 'commonName' => 'test-idp', 'countryName' => 'IT' ), $key, $cfg );
	$crt = openssl_csr_sign( $csr, null, $key, 30, $cfg );
	openssl_x509_export( $crt, $cert );
	openssl_pkey_export( $key, $priv );
	return array( $priv, $cert );
}

const SP    = 'https://sp.example.it';
const IDP   = 'https://idp.example.it';
const ACS   = 'https://sp.example.it/?wpspid=acs';
const REQID = 'wpspid_abc123';

/**
 * Build a Response XML string (unsigned).
 */
function build_response( array $o = array() ) {
	$o = array_merge( array(
		'now'         => time(),
		'level'       => 'https://www.spid.gov.it/SpidL2',
		'irt'         => REQID,
		'dest'        => ACS,
		'recipient'   => ACS,
		'issuer'      => IDP,
		'aud'         => SP,
		'fiscal'      => 'TINIT-RSSMRA80A01H501U',
		'issuer_fmt'  => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
		'attr_extra'  => '',
		'omit_attrs'  => array(),
	), $o );
	$now = $o['now'];
	$ii  = gmdate( 'Y-m-d\TH:i:s\Z', $now );
	$nb  = gmdate( 'Y-m-d\TH:i:s\Z', $now - 10 );
	$na  = gmdate( 'Y-m-d\TH:i:s\Z', $now + 300 );
	$attrs = array( 'fiscalNumber' => $o['fiscal'], 'name' => 'Mario', 'familyName' => 'Rossi', 'email' => 'm@example.it', 'dateOfBirth' => '1980-01-01' );
	$attr_xml = '';
	foreach ( $attrs as $k => $v ) {
		if ( in_array( $k, $o['omit_attrs'], true ) ) {
			continue;
		}
		$attr_xml .= '<saml:Attribute Name="' . $k . '"><saml:AttributeValue>' . htmlspecialchars( $v ) . '</saml:AttributeValue></saml:Attribute>';
	}
	$fmt = $o['issuer_fmt'] ? ' Format="' . $o['issuer_fmt'] . '"' : '';
	$xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
		. ' ID="_resp1" Version="2.0" IssueInstant="' . $ii . '" Destination="' . $o['dest'] . '" InResponseTo="' . $o['irt'] . '">'
		. '<saml:Issuer' . $fmt . '>' . $o['issuer'] . '</saml:Issuer>'
		. '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
		. '<saml:Assertion ID="_assert1" Version="2.0" IssueInstant="' . $ii . '">'
		. '<saml:Issuer' . $fmt . '>' . $o['issuer'] . '</saml:Issuer>'
		. '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="' . IDP . '">tid-1</saml:NameID>'
		. '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="' . $o['recipient'] . '" InResponseTo="' . $o['irt'] . '" NotOnOrAfter="' . $na . '"/></saml:SubjectConfirmation></saml:Subject>'
		. '<saml:Conditions NotBefore="' . $nb . '" NotOnOrAfter="' . $na . '"><saml:AudienceRestriction><saml:Audience>' . $o['aud'] . '</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
		. '<saml:AuthnStatement AuthnInstant="' . $ii . '" SessionIndex="sess-1"><saml:AuthnContext><saml:AuthnContextClassRef>' . $o['level'] . '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
		. '<saml:AttributeStatement>' . $attr_xml . $o['attr_extra'] . '</saml:AttributeStatement>'
		. '</saml:Assertion></samlp:Response>';
	return $xml;
}

/** Sign assertion (and optionally response) and return base64 for validate(). */
function signed_b64( $xml, $priv, $cert, $sign_assertion = true, $sign_response = false, callable $tamper = null ) {
	$doc = XmlSecurity::load_xml( $xml );
	$xp  = XmlSecurity::get_xpath( $doc );
	if ( $sign_assertion ) {
		Signer::sign( $xp->query( '//saml:Assertion' )->item( 0 ), $priv, $cert );
	}
	if ( $sign_response ) {
		Signer::sign( $doc->documentElement, $priv, $cert );
	}
	$out = $doc->saveXML();
	if ( $tamper ) {
		$out = $tamper( $out );
	}
	return base64_encode( $out );
}

function expectations( array $o = array() ) {
	global $CERT;
	return array_merge( array(
		'request_id'          => REQID,
		'idp_entity_id'       => IDP,
		'certs'               => array( $CERT ),
		'sp_entity_id'        => SP,
		'acs_url'             => ACS,
		'level'               => 2,
		'comparison'          => 'minimum',
		'service'             => 'spid',
		'required_attributes' => array( 'fiscalNumber', 'name', 'familyName', 'email', 'dateOfBirth' ),
	), $o );
}

list( $PRIV, $CERT ) = make_keypair();
list( $PRIV2, $CERT2 ) = make_keypair(); // attacker / wrong key.

echo "== Positive\n";
$res = ResponseValidator::validate( signed_b64( build_response(), $PRIV, $CERT ), expectations() );
ok( 'RSSMRA80A01H501U' === $res['attributes']['fiscalNumber'], 'valid response accepted, TINIT- stripped' );
ok( 'sess-1' === $res['session_index'] && '_assert1' === $res['assertion_id'], 'session index / assertion id returned' );

$res = ResponseValidator::validate( signed_b64( build_response(), $PRIV, $CERT, true, true ), expectations() );
ok( true, 'assertion + response both signed accepted (nested signatures)' );

$res = ResponseValidator::validate( signed_b64( build_response( array( 'level' => 'https://www.spid.gov.it/SpidL3' ) ), $PRIV, $CERT ), expectations() );
ok( true, 'higher level accepted with comparison=minimum' );

$res = ResponseValidator::validate(
	signed_b64( build_response( array( 'issuer_fmt' => '', 'level' => 'urn:custom:cie' ) ), $PRIV, $CERT ),
	expectations( array( 'service' => 'cie', 'required_attributes' => array( 'fiscalNumber', 'name' ) ) )
);
ok( true, 'CIE branch: no Issuer Format / unknown class ref accepted' );

echo "== Signature attacks\n";
rejects( 'unsigned assertion', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response(), $PRIV, $CERT, false ), expectations() );
}, 'signature' );

rejects( 'wrong signing key', function () use ( $PRIV2, $CERT2 ) {
	ResponseValidator::validate( signed_b64( build_response(), $PRIV2, $CERT2 ), expectations() );
}, 'signature' );

rejects( 'attribute tampered after signing', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response(), $PRIV, $CERT, true, false, function ( $x ) {
		return str_replace( 'TINIT-RSSMRA80A01H501U', 'TINIT-VRDLGI90B02F205X', $x );
	} );
	ResponseValidator::validate( $b64, expectations() );
}, 'signature' );

rejects( 'forged unsigned assertion next to a signed one (wrapping)', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response(), $PRIV, $CERT, true, false, function ( $x ) {
		$forged = '<saml:Assertion ID="_evil" Version="2.0"><saml:AttributeStatement><saml:Attribute Name="fiscalNumber"><saml:AttributeValue>TINIT-VICTIM</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>';
		return str_replace( '</samlp:Response>', $forged . '</samlp:Response>', $x );
	} );
	ResponseValidator::validate( $b64, expectations() );
}, 'structure' );

rejects( 'signed assertion hidden in Extensions, forged one on top (wrapping)', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response(), $PRIV, $CERT, true, false, function ( $x ) {
		// Move the genuine signed assertion inside samlp:Extensions and add forged top-level one.
		preg_match( '#<saml:Assertion .*</saml:Assertion>#s', $x, $m );
		$forged = str_replace( '_assert1', '_evil', $m[0] );
		$forged = preg_replace( '#<ds:Signature.*</ds:Signature>#s', '', $forged );
		$forged = str_replace( 'TINIT-RSSMRA80A01H501U', 'TINIT-VICTIM', $forged );
		$x = str_replace( $m[0], '<samlp:Extensions>' . $m[0] . '</samlp:Extensions>' . $forged, $x );
		return $x;
	} );
	ResponseValidator::validate( $b64, expectations() );
} );

rejects( 'Reference URI with quote injection', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response(), $PRIV, $CERT, true, false, function ( $x ) {
		return str_replace( 'URI="#_assert1"', 'URI="#_assert1&quot; or &quot;1&quot;=&quot;1"', $x );
	} );
	ResponseValidator::validate( $b64, expectations() );
}, 'signature' );

rejects( 'SHA-1 signature algorithm', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response(), $PRIV, $CERT, true, false, function ( $x ) {
		return str_replace( 'xmldsig-more#rsa-sha256', 'xmldsig#rsa-sha1', $x );
	} );
	ResponseValidator::validate( $b64, expectations() );
}, 'signature' );

rejects( 'duplicate ID attribute elsewhere in document', function () use ( $PRIV, $CERT ) {
	$b64 = signed_b64( build_response( array( 'attr_extra' => '<saml:Attribute Name="x" ID="_assert1"><saml:AttributeValue>1</saml:AttributeValue></saml:Attribute>' ) ), $PRIV, $CERT );
	ResponseValidator::validate( $b64, expectations() );
}, 'signature' );

rejects( 'DOCTYPE / XXE', function () use ( $PRIV, $CERT ) {
	$xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>' . build_response();
	ResponseValidator::validate( base64_encode( $xml ), expectations() );
} );

echo "== Content checks (all validly signed)\n";
rejects( 'wrong InResponseTo', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'irt' => 'other' ) ), $PRIV, $CERT ), expectations() );
}, 'in_response_to' );
rejects( 'missing InResponseTo', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'irt' => '' ) ), $PRIV, $CERT ), expectations() );
}, 'in_response_to' );
rejects( 'wrong Destination', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'dest' => 'https://evil.example/acs' ) ), $PRIV, $CERT ), expectations() );
}, 'destination' );
rejects( 'wrong Recipient', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'recipient' => 'https://evil.example/acs' ) ), $PRIV, $CERT ), expectations() );
}, 'recipient' );
rejects( 'wrong Issuer', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'issuer' => 'https://other-idp.example' ) ), $PRIV, $CERT ), expectations() );
}, 'issuer' );
rejects( 'wrong Issuer Format (SPID)', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'issuer_fmt' => '' ) ), $PRIV, $CERT ), expectations() );
}, 'issuer' );
rejects( 'wrong Audience', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'aud' => 'https://another-sp.example' ) ), $PRIV, $CERT ), expectations() );
}, 'audience' );
rejects( 'expired (old IssueInstant)', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'now' => time() - 3600 ) ), $PRIV, $CERT ), expectations() );
}, 'expired' );
rejects( 'issued in the future', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'now' => time() + 3600 ) ), $PRIV, $CERT ), expectations() );
}, 'expired' );
rejects( 'level lower than requested (minimum)', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'level' => 'https://www.spid.gov.it/SpidL1' ) ), $PRIV, $CERT ), expectations() );
}, 'level' );
rejects( 'level different (exact)', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'level' => 'https://www.spid.gov.it/SpidL3' ) ), $PRIV, $CERT ), expectations( array( 'comparison' => 'exact' ) ) );
}, 'level' );
rejects( 'invalid class ref (SPID)', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'level' => 'https://www.spid.gov.it/SpidL9' ) ), $PRIV, $CERT ), expectations() );
}, 'authn' );
rejects( 'missing required attribute', function () use ( $PRIV, $CERT ) {
	ResponseValidator::validate( signed_b64( build_response( array( 'omit_attrs' => array( 'email' ) ) ), $PRIV, $CERT ), expectations() );
}, 'attributes' );
rejects( 'IdP error status', function () {
	$xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/><samlp:StatusMessage>ErrorCode nr25</samlp:StatusMessage></samlp:Status></samlp:Response>';
	ResponseValidator::validate( base64_encode( $xml ), expectations() );
}, 'idp_error' );
rejects( 'garbage base64', function () {
	ResponseValidator::validate( '%%%not-base64%%%', expectations() );
}, 'structure' );

echo "== Signer / verifier round trip on other elements\n";
$doc = XmlSecurity::load_xml( '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_md1" entityID="x"><md:A/></md:EntityDescriptor>' );
Signer::sign( $doc->documentElement, $PRIV, $CERT );
$reloaded = XmlSecurity::load_xml( $doc->saveXML() );
$threw = false;
try {
	SignatureVerifier::verify_element( $reloaded, $reloaded->documentElement, array( $CERT ) );
} catch ( \Exception $e ) {
	$threw = true;
	echo '    ' . $e->getMessage() . "\n";
}
ok( ! $threw, 'metadata-like document: sign -> reload -> verify' );
ok( preg_match( '#^<\?xml[^>]*\?>\s*<md:EntityDescriptor[^>]*>\s*<ds:Signature#', $doc->saveXML() ) === 1, 'Signature is first child of EntityDescriptor' );

echo "\n{$GLOBALS['pass']} passed, {$GLOBALS['fail']} failed\n";
exit( $GLOBALS['fail'] ? 1 : 0 );
