<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- i messaggi delle eccezioni non vengono stampati direttamente: chi li mostra li esegue con esc_html().
namespace AuthSpidCie\Cert;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cifratura facoltativa della chiave privata (libsodium).
 *
 * Se in wp-config.php e' definita `AUTHSPIDCIE_SECRET` (stringa non vuota) la chiave si salva cifrata con
 * `sodium_crypto_secretbox`; altrimenti in chiaro. Il blob porta un marcatore di versione e di
 * "cifrato si'/no" e, se cifrato, un'impronta breve della chiave derivata: cosi' si distingue
 * "costante assente" da "costante diversa" da "dato danneggiato" e non si restituisce mai una chiave
 * sbagliata. Non si cifra con i salt di WordPress (ruotarli renderebbe la chiave illeggibile).
 *
 * Formato:  authspidcie:1:plain:<PEM>   |   authspidcie:1:enc:<fingerprint>:<base64(nonce . cifrato)>
 */
class KeyVault {

	const PREFIX  = 'authspidcie:1:';
	const CONTEXT = 'auth-spid-cie|key|v1';

	const S_OK            = 'ok';            // Cifrata e leggibile.
	const S_PLAIN         = 'plain';         // In chiaro, nessuna costante definita.
	const S_PLAIN_PENDING = 'plain_pending'; // In chiaro ma la costante e' definita: leggibile, da cifrare.
	const S_NO_SECRET     = 'no_secret';     // Cifrata, costante assente.
	const S_WRONG_SECRET  = 'wrong_secret';  // Cifrata con un'altra costante.
	const S_NO_SODIUM     = 'no_sodium';     // Serve libsodium e non c'e'.
	const S_CORRUPT       = 'corrupt';       // Formato sconosciuto o dato alterato.
	const S_MISSING       = 'missing';       // Nessun dato.

	/** Solo per i test (una costante PHP non si puo' ridefinire): simula AUTHSPIDCIE_SECRET. */
	public static $test_secret = null;
	/** Solo per i test: simula l'assenza di libsodium. */
	public static $test_no_sodium = false;

	/** @return string Segreto di wp-config.php o stringa vuota. */
	public static function secret() {
		if ( null !== self::$test_secret ) {
			return (string) self::$test_secret;
		}
		return ( defined( 'AUTHSPIDCIE_SECRET' ) && is_string( AUTHSPIDCIE_SECRET ) ) ? AUTHSPIDCIE_SECRET : '';
	}

	public static function has_secret() {
		return '' !== self::secret();
	}

	public static function sodium_available() {
		return ! self::$test_no_sodium && function_exists( 'sodium_crypto_secretbox' ) && function_exists( 'sodium_crypto_generichash' );
	}

	private static function derive() {
		return sodium_crypto_generichash( self::CONTEXT . "\0" . self::secret(), '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}

	private static function fingerprint( $key ) {
		return substr( bin2hex( sodium_crypto_generichash( 'fingerprint|' . $key, '', 32 ) ), 0, 16 );
	}

	/**
	 * Prepara la chiave per il salvataggio.
	 *
	 * @param string $pem Chiave privata PEM.
	 * @return string Blob.
	 * @throws \Exception Se la costante e' definita ma libsodium manca.
	 */
	public static function seal( $pem ) {
		if ( ! self::has_secret() ) {
			return self::PREFIX . 'plain:' . $pem;
		}
		if ( ! self::sodium_available() ) {
			throw new \Exception( self::message( self::S_NO_SODIUM ) );
		}
		$key    = self::derive();
		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = sodium_crypto_secretbox( $pem, $nonce, $key );
		$fp     = self::fingerprint( $key );
		sodium_memzero( $key );
		return self::PREFIX . 'enc:' . $fp . ':' . base64_encode( $nonce . $cipher );
	}

	/**
	 * Legge il blob.
	 *
	 * @param mixed $blob Valore salvato.
	 * @return array {status:string, key:string|false} `key` e' valorizzata solo se e' sicuramente quella giusta.
	 */
	public static function open( $blob ) {
		if ( ! is_string( $blob ) || '' === $blob ) {
			return array( 'status' => self::S_MISSING, 'key' => false );
		}
		if ( 0 !== strpos( $blob, self::PREFIX ) ) {
			return array( 'status' => self::S_CORRUPT, 'key' => false );
		}
		$rest = substr( $blob, strlen( self::PREFIX ) );

		if ( 0 === strpos( $rest, 'plain:' ) ) {
			$pem = substr( $rest, 6 );
			if ( '' === $pem ) {
				return array( 'status' => self::S_CORRUPT, 'key' => false );
			}
			if ( self::has_secret() ) {
				// Blocca solo se manca libsodium: la costante promette una cifratura che non si puo' fare.
				if ( ! self::sodium_available() ) {
					return array( 'status' => self::S_NO_SODIUM, 'key' => false );
				}
				return array( 'status' => self::S_PLAIN_PENDING, 'key' => $pem );
			}
			return array( 'status' => self::S_PLAIN, 'key' => $pem );
		}

		if ( 0 === strpos( $rest, 'enc:' ) ) {
			$parts = explode( ':', substr( $rest, 4 ), 2 );
			if ( 2 !== count( $parts ) || ! preg_match( '/^[a-f0-9]{16}$/', $parts[0] ) ) {
				return array( 'status' => self::S_CORRUPT, 'key' => false );
			}
			if ( ! self::sodium_available() ) {
				return array( 'status' => self::S_NO_SODIUM, 'key' => false );
			}
			if ( ! self::has_secret() ) {
				return array( 'status' => self::S_NO_SECRET, 'key' => false );
			}
			$key = self::derive();
			if ( ! hash_equals( $parts[0], self::fingerprint( $key ) ) ) {
				sodium_memzero( $key );
				return array( 'status' => self::S_WRONG_SECRET, 'key' => false );
			}
			$raw = base64_decode( $parts[1], true );
			if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				sodium_memzero( $key );
				return array( 'status' => self::S_CORRUPT, 'key' => false );
			}
			$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plain = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, $key );
			sodium_memzero( $key );
			if ( false === $plain || '' === $plain ) {
				return array( 'status' => self::S_CORRUPT, 'key' => false );
			}
			return array( 'status' => self::S_OK, 'key' => $plain );
		}

		return array( 'status' => self::S_CORRUPT, 'key' => false );
	}

	/** True se lo stato permette di usare la chiave. */
	public static function is_readable_status( $status ) {
		return in_array( $status, array( self::S_OK, self::S_PLAIN, self::S_PLAIN_PENDING ), true );
	}

	/** Messaggio per un amministratore, per gli stati che impediscono di usare la chiave. */
	public static function message( $status ) {
		$tail = __( 'Restore the original AUTHSPIDCIE_SECRET constant or generate a new certificate (it will have to be registered again with AgID/CIE).', 'auth-spid-cie' );
		switch ( $status ) {
			case self::S_NO_SECRET:
				return __( 'The private key is unreadable: it is stored encrypted but AUTHSPIDCIE_SECRET is not defined in wp-config.php.', 'auth-spid-cie' ) . ' ' . $tail;
			case self::S_WRONG_SECRET:
				return __( 'The private key is unreadable: it was encrypted with a different AUTHSPIDCIE_SECRET.', 'auth-spid-cie' ) . ' ' . $tail;
			case self::S_NO_SODIUM:
				return __( 'The private key cannot be used: the PHP sodium extension is not available but is needed (AUTHSPIDCIE_SECRET is defined or the key is stored encrypted). Enable the extension, or remove the constant if the key was never encrypted.', 'auth-spid-cie' );
			case self::S_CORRUPT:
				return __( 'The private key is unreadable: the stored data is damaged or in an unknown format.', 'auth-spid-cie' ) . ' ' . __( 'Generate a new certificate (it will have to be registered again with AgID/CIE) or restore a backup of the database.', 'auth-spid-cie' );
			case self::S_MISSING:
				return __( 'Certificate or private key missing.', 'auth-spid-cie' );
		}
		return '';
	}
}
