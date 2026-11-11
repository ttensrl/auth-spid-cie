<?php
namespace WpSpidCie\Saml;

use WpSpidCie\Cert\CertificateManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles SAML HTTP-Redirect and HTTP-POST bindings.
 */
class Bindings {

	/**
	 * Send SAML request via HTTP-Redirect.
	 *
	 * @param string $sso_url
	 * @param string $saml_request_xml
	 * @param string $relay_state
	 * @param string $service 'spid' or 'cie'
	 * @return string Redirect URL with signed query string.
	 */
	public static function build_redirect_url( $sso_url, $saml_request_xml, $relay_state = '', $service = 'spid' ) {
		$deflated = gzdeflate( $saml_request_xml );
		$base64 = base64_encode( $deflated );
		
		$query = 'SAMLRequest=' . rawurlencode( $base64 );
		if ( ! empty( $relay_state ) ) {
			$query .= '&RelayState=' . rawurlencode( $relay_state );
		}

		$sig_alg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
		$query .= '&SigAlg=' . rawurlencode( $sig_alg );

		$private_key = CertificateManager::private_key_or_fail( $service );
		$signature   = '';
		if ( ! openssl_sign( $query, $signature, $private_key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \Exception( 'Unable to sign the request (HTTP-Redirect).' );
		}
		$query .= '&Signature=' . rawurlencode( base64_encode( $signature ) );

		return $sso_url . ( strpos( $sso_url, '?' ) !== false ? '&' : '?' ) . $query;
	}

	public static function send_redirect( $sso_url, $saml_request_xml, $relay_state = '', $service = 'spid' ) {
		wp_redirect( self::build_redirect_url( $sso_url, $saml_request_xml, $relay_state, $service ) ); // phpcs:ignore WordPress.Security.SafeRedirect -- IdP URL from trusted registry.
		exit;
	}

	/**
	 * Render HTML auto-submit form for HTTP-POST binding.
	 *
	 * @param string $sso_url
	 * @param string $saml_request_xml
	 * @param string $relay_state
	 * @return void
	 */
	public static function send_post( $sso_url, $saml_request_xml, $relay_state = '' ) {
		$base64 = base64_encode( $saml_request_xml );
		
		header( 'Content-Type: text/html; charset=UTF-8' );
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<title><?php echo esc_html__( 'Redirecting...', 'auth-spid-cie' ); ?></title>
		</head>
		<body onload="document.forms[0].submit();">
			<p><?php echo esc_html__( 'Redirecting to the identity provider...', 'auth-spid-cie' ); ?></p>
			<form method="post" action="<?php echo esc_url( $sso_url ); ?>">
				<input type="hidden" name="SAMLRequest" value="<?php echo esc_attr( $base64 ); ?>" />
				<?php if ( ! empty( $relay_state ) ) : ?>
					<input type="hidden" name="RelayState" value="<?php echo esc_attr( $relay_state ); ?>" />
				<?php endif; ?>
				<noscript>
					<input type="submit" value="<?php echo esc_attr__( 'Click here to continue', 'auth-spid-cie' ); ?>" />
				</noscript>
			</form>
		</body>
		</html>
		<?php
		exit;
	}
}
