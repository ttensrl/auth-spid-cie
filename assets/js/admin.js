/*
 * Auth SPID CIE settings screen. Progressive enhancement only: without JavaScript every field
 * stays visible and every form still works.
 */
( function () {
	'use strict';

	var root = document.querySelector( '.authspidcie-admin' );
	if ( ! root ) {
		return;
	}
	var OPT = 'authspidcie_options';

	function field( name ) {
		return root.querySelector( '[name="' + OPT + '[' + name + ']"]' );
	}

	// Show the blocks that apply to the chosen entity type / enabled services.
	function applyVisibility() {
		var cie = field( 'cie_enabled' );
		var type = field( 'sp_type' );
		var isCie = ! cie || cie.checked;
		var isPrivate = type ? type.value === 'private' : false;

		root.querySelectorAll( '[data-authspidcie-when]' ).forEach( function ( el ) {
			var when = el.getAttribute( 'data-authspidcie-when' );
			var show = true;
			if ( when === 'cie' ) {
				show = isCie;
			} else if ( when === 'private' ) {
				show = isPrivate;
			} else if ( when === 'public' ) {
				show = ! isPrivate;
			}
			el.hidden = ! show;
		} );

		root.querySelectorAll( '[data-label-public]' ).forEach( function ( label ) {
			var text = label.querySelector( '.authspidcie-label-text' );
			if ( text ) {
				text.textContent = label.getAttribute( isPrivate ? 'data-label-private' : 'data-label-public' );
			}
		} );
	}

	[ 'cie_enabled', 'sp_type' ].forEach( function ( name ) {
		var el = field( name );
		if ( el ) {
			el.addEventListener( 'change', applyVisibility );
		}
	} );
	applyVisibility();

	// "Use the address of this site".
	root.querySelectorAll( '.authspidcie-use-site' ).forEach( function ( btn ) {
		btn.addEventListener( 'click', function () {
			var input = document.getElementById( btn.getAttribute( 'data-target' ) );
			if ( input ) {
				input.value = btn.getAttribute( 'data-value' );
				input.dispatchEvent( new Event( 'input', { bubbles: true } ) );
				input.focus();
			}
		} );
	} );

	// Copy a metadata address.
	root.querySelectorAll( '.authspidcie-copy' ).forEach( function ( btn ) {
		btn.addEventListener( 'click', function () {
			var text = btn.getAttribute( 'data-copy' );
			var done = function () {
				var old = btn.textContent;
				btn.textContent = btn.getAttribute( 'data-done' ) || old;
				window.setTimeout( function () {
					btn.textContent = old;
				}, 1500 );
			};
			if ( navigator.clipboard && navigator.clipboard.writeText ) {
				navigator.clipboard.writeText( text ).then( done );
				return;
			}
			var tmp = document.createElement( 'textarea' );
			tmp.value = text;
			document.body.appendChild( tmp );
			tmp.select();
			try {
				document.execCommand( 'copy' );
				done();
			} catch ( e ) {}
			document.body.removeChild( tmp );
		} );
	} );

	// Replacing a certificate needs the confirmation box: keep the button off until it is ticked.
	root.querySelectorAll( '.authspidcie-confirm-form' ).forEach( function ( form ) {
		var box = form.querySelector( '.authspidcie-confirm' );
		var button = form.querySelector( 'input[type="submit"], button[type="submit"]' );
		if ( ! box || ! button ) {
			return;
		}
		var sync = function () {
			button.disabled = ! box.checked;
		};
		box.addEventListener( 'change', sync );
		sync();
	} );

	// A link to a section hidden inside a <details> opens it.
	function openTarget() {
		if ( ! window.location.hash ) {
			return;
		}
		var el = document.getElementById( window.location.hash.slice( 1 ) );
		while ( el && el !== root ) {
			if ( el.tagName === 'DETAILS' ) {
				el.open = true;
			}
			el = el.parentElement;
		}
	}
	window.addEventListener( 'hashchange', openTarget );
	openTarget();
}() );
