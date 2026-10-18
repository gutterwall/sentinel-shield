/**
 * Sentinel Shield passkeys: runs the browser's WebAuthn ceremonies.
 *
 * Buttons with data-ss-passkey="create" or "get" carry the server's options
 * (binary values as base64url) in data-options. The result is written as JSON
 * into the form field named by data-field, and the form is submitted.
 */
( function () {
	'use strict';

	function enc( buffer ) {
		var bytes = new Uint8Array( buffer ), text = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			text += String.fromCharCode( bytes[ i ] );
		}
		return btoa( text ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function dec( text ) {
		var b64 = text.replace( /-/g, '+' ).replace( /_/g, '/' );
		b64 += '==='.slice( ( b64.length + 3 ) % 4 );
		var raw = atob( b64 ), out = new Uint8Array( raw.length );
		for ( var i = 0; i < raw.length; i++ ) {
			out[ i ] = raw.charCodeAt( i );
		}
		return out;
	}

	function creds( list ) {
		return ( list || [] ).map( function ( c ) {
			return { type: c.type, id: dec( c.id ) };
		} );
	}

	var api = {
		supported: function () {
			return !! ( window.PublicKeyCredential && navigator.credentials && window.isSecureContext );
		},
		create: function ( o ) {
			o.challenge = dec( o.challenge );
			o.user.id = dec( o.user.id );
			o.excludeCredentials = creds( o.excludeCredentials );
			return navigator.credentials.create( { publicKey: o } ).then( function ( c ) {
				return { client: enc( c.response.clientDataJSON ), attestation: enc( c.response.attestationObject ) };
			} );
		},
		get: function ( o ) {
			o.challenge = dec( o.challenge );
			o.allowCredentials = creds( o.allowCredentials );
			return navigator.credentials.get( { publicKey: o } ).then( function ( a ) {
				return {
					id: enc( a.rawId ),
					client: enc( a.response.clientDataJSON ),
					auth: enc( a.response.authenticatorData ),
					signature: enc( a.response.signature )
				};
			} );
		}
	};
	window.SentinelShieldPasskey = api;

	function ready() {
		document.querySelectorAll( '[data-ss-passkey]' ).forEach( function ( button ) {
			if ( ! api.supported() ) {
				button.disabled = true;
				var note = button.closest( 'form' ) && button.closest( 'form' ).querySelector( '.ss-passkey-error' );
				if ( note ) {
					note.textContent = window.isSecureContext ? 'This browser does not support passkeys.' : 'Passkeys need an https:// address.';
				}
			}
		} );
	}
	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', ready );
	} else {
		ready();
	}

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest ? event.target.closest( '[data-ss-passkey]' ) : null;
		if ( ! button ) {
			return;
		}
		event.preventDefault();
		var form = button.closest( 'form' ), note = form.querySelector( '.ss-passkey-error' );
		var run = 'create' === button.getAttribute( 'data-ss-passkey' ) ? api.create : api.get;
		if ( note ) {
			note.textContent = '';
		}
		button.disabled = true;
		run( JSON.parse( button.getAttribute( 'data-options' ) ) ).then( function ( result ) {
			form.querySelector( '[name="' + button.getAttribute( 'data-field' ) + '"]' ).value = JSON.stringify( result );
			// Not form.submit(): a field named "submit" (WordPress buttons) would shadow it.
			HTMLFormElement.prototype.submit.call( form );
		} ).catch( function ( error ) {
			button.disabled = false;
			if ( note ) {
				note.textContent = error && 'NotAllowedError' === error.name ? 'Cancelled, or no matching passkey on this device.' : ( error && error.message ? error.message : String( error ) );
			}
		} );
	} );
}() );
