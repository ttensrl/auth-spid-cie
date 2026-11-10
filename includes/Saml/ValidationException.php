<?php
namespace WpSpidCie\Saml;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Raised when a SAML message fails validation.
 *
 * $reason is a stable machine slug; $details carries extra context for logs
 * (never shown to the end user verbatim).
 */
class ValidationException extends \Exception {
	/** @var string */
	public $reason;
	/** @var array */
	public $details;

	public function __construct( $message, $reason = 'invalid', array $details = array() ) {
		parent::__construct( $message );
		$this->reason  = $reason;
		$this->details = $details;
	}
}
