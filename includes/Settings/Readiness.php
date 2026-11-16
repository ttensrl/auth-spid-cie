<?php
namespace AuthSpidCie\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * "Is this site ready?" logic for the settings screen, kept free of HTML so it can be tested:
 * the state of each service (traffic light) and the guided checklist with its next step.
 */
class Readiness {

	const READY          = 'ready';
	const OFF            = 'off';
	const BLOCKED        = 'blocked';
	const MISSING_DATA   = 'missing_data';
	const NO_CERT        = 'no_cert';
	const KEY_UNREADABLE = 'key_unreadable';

	/**
	 * State of one service.
	 *
	 * @param string $service 'spid' or 'cie'.
	 * @param array  $in      {enabled:bool, probe_ok:bool, missing:string[], has_cert:bool, key_ok:bool}
	 * @return array {state, tone (ok|bad|off), label, text, missing}
	 */
	public static function service( $service, array $in ) {
		$in      = $in + array( 'enabled' => true, 'probe_ok' => true, 'missing' => array(), 'has_cert' => false, 'key_ok' => false );
		$missing = array_values( (array) $in['missing'] );
		$name    = 'cie' === $service ? 'CIE' : 'SPID';

		if ( ! $in['enabled'] ) {
			return array( 'state' => self::OFF, 'tone' => 'off', 'label' => __( 'Not active', 'auth-spid-cie' ), 'text' => sprintf( /* translators: %s: SPID or CIE. */ __( 'Login with %s is turned off in the settings.', 'auth-spid-cie' ), $name ), 'missing' => array() );
		}
		if ( ! $in['probe_ok'] ) {
			return array( 'state' => self::BLOCKED, 'tone' => 'bad', 'label' => __( 'Blocked by the server', 'auth-spid-cie' ), 'text' => __( 'This server cannot create or use certificates (see the technical details below).', 'auth-spid-cie' ), 'missing' => array() );
		}
		if ( $missing ) {
			return array( 'state' => self::MISSING_DATA, 'tone' => 'bad', 'label' => __( 'Data missing', 'auth-spid-cie' ), 'text' => sprintf( /* translators: %s: list of missing fields. */ __( 'Fill in and save: %s.', 'auth-spid-cie' ), implode( ', ', $missing ) ), 'missing' => $missing );
		}
		if ( ! $in['has_cert'] ) {
			return array( 'state' => self::NO_CERT, 'tone' => 'bad', 'label' => __( 'Certificate missing', 'auth-spid-cie' ), 'text' => __( 'Generate the certificate (or import the one you already registered) in the Certificates section.', 'auth-spid-cie' ), 'missing' => array() );
		}
		if ( ! $in['key_ok'] ) {
			return array( 'state' => self::KEY_UNREADABLE, 'tone' => 'bad', 'label' => __( 'Private key unreadable', 'auth-spid-cie' ), 'text' => __( 'The private key cannot be read: see the message below.', 'auth-spid-cie' ), 'missing' => array() );
		}
		return array( 'state' => self::READY, 'tone' => 'ok', 'label' => __( 'Ready', 'auth-spid-cie' ), 'text' => __( 'The metadata is ready to be downloaded and registered.', 'auth-spid-cie' ), 'missing' => array() );
	}

	/**
	 * Guided checklist.
	 *
	 * @param array $opts      Plugin options.
	 * @param array $services  Result of service() per service ('spid' / 'cie').
	 * @param array $snapshots Per service: 'none' | 'same' | 'changed' (copy of the registered metadata).
	 * @return array {steps: array[] {id, status (done|todo|warn), title, text, anchor}, next: array|null}
	 */
	public static function checklist( array $opts, array $services, array $snapshots = array() ) {
		$active = array();
		foreach ( $services as $s => $info ) {
			if ( self::OFF !== $info['state'] ) {
				$active[] = $s;
			}
		}
		$states = function ( array $wanted ) use ( $active, $services ) {
			foreach ( $active as $s ) {
				if ( in_array( $services[ $s ]['state'], $wanted, true ) ) {
					return true;
				}
			}
			return false;
		};

		// 1. Organization data.
		if ( ! $active ) {
			$org = array( 'todo', __( 'Turn on SPID and/or CIE in the Login box of the Organization section, then fill in the organization data.', 'auth-spid-cie' ) );
		} elseif ( $states( array( self::MISSING_DATA ) ) ) {
			$org = array( 'todo', __( 'Some data is still missing: the status cards below list it.', 'auth-spid-cie' ) );
		} else {
			$org = array( 'done', __( 'The organization data is complete.', 'auth-spid-cie' ) );
		}

		// 2. Certificate.
		if ( ! $active ) {
			$cert = array( 'todo', __( 'Needed after the organization data.', 'auth-spid-cie' ) );
		} elseif ( $states( array( self::BLOCKED, self::KEY_UNREADABLE ) ) ) {
			$cert = array( 'warn', __( 'There is a problem with the key or the server: see the status cards below.', 'auth-spid-cie' ) );
		} elseif ( $states( array( self::MISSING_DATA ) ) ) {
			$cert = array( 'todo', __( 'It signs the metadata and the login requests. Generate it after saving the organization data.', 'auth-spid-cie' ) );
		} elseif ( $states( array( self::NO_CERT ) ) ) {
			$cert = array( 'todo', __( 'Generate it, or import the one you already registered, in the Certificates section.', 'auth-spid-cie' ) );
		} else {
			$cert = array( 'done', __( 'The certificate is in place.', 'auth-spid-cie' ) );
		}

		// 3. Metadata registered.
		$register_text = __( 'Registering the metadata means handing the file that describes your site to the body that will recognise it: the SPID Demo test environment (through the Validator) while you test, AgID for the real SPID, the Ministry of the Interior for CIE. Download the metadata from the status card and upload it there; then save a copy here so the plugin warns you if it changes.', 'auth-spid-cie' );
		$snap          = array();
		foreach ( $active as $s ) {
			$snap[] = isset( $snapshots[ $s ] ) ? $snapshots[ $s ] : 'none';
		}
		if ( ! $active || in_array( 'none', $snap, true ) ) {
			$reg = array( 'todo', $register_text );
		} elseif ( in_array( 'changed', $snap, true ) ) {
			$reg = array( 'warn', __( 'The metadata is different from the copy you saved: if the change is intended, register it again and save a new copy.', 'auth-spid-cie' ) );
		} else {
			$reg = array( 'done', __( 'You saved a copy of the registered metadata and it has not changed.', 'auth-spid-cie' ) );
		}

		// 4. Login enabled and tried.
		$login = ! empty( $opts['enabled'] )
			? array( 'done', __( 'Login is enabled. Try it with a test provider from the login page.', 'auth-spid-cie' ) )
			: array( 'todo', __( 'Tick "Enable login" in the Organization section, save, then try it with a test provider (SPID Demo) from the login page.', 'auth-spid-cie' ) );

		// 5. Production.
		$prod = ! empty( $opts['production'] )
			? array( 'done', __( 'The site is in production: test providers are hidden.', 'auth-spid-cie' ) )
			: array( 'todo', __( 'Only when AgID/the Ministry have accepted your registration: tick "Production environment" in the Tests section.', 'auth-spid-cie' ) );

		$steps = array(
			array( 'id' => 'org', 'status' => $org[0], 'title' => __( 'Fill in the organization data', 'auth-spid-cie' ), 'text' => $org[1], 'anchor' => 'authspidcie-ente' ),
			array( 'id' => 'cert', 'status' => $cert[0], 'title' => __( 'Generate or import the certificate', 'auth-spid-cie' ), 'text' => $cert[1], 'anchor' => 'authspidcie-certificati' ),
			array( 'id' => 'register', 'status' => $reg[0], 'title' => __( 'Download the metadata and register it', 'auth-spid-cie' ), 'text' => $reg[1], 'anchor' => 'authspidcie-stato' ),
			array( 'id' => 'login', 'status' => $login[0], 'title' => __( 'Enable login and try it with a test provider', 'auth-spid-cie' ), 'text' => $login[1], 'anchor' => 'authspidcie-prove' ),
			array( 'id' => 'prod', 'status' => $prod[0], 'title' => __( 'Go to production', 'auth-spid-cie' ), 'text' => $prod[1], 'anchor' => 'authspidcie-prove' ),
		);
		$next = null;
		foreach ( $steps as $i => $step ) {
			if ( 'done' !== $step['status'] ) {
				$next = $step + array( 'number' => $i + 1 );
				break;
			}
		}
		return array( 'steps' => $steps, 'next' => $next );
	}
}
