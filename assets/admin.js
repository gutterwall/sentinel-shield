/* Sentinel Shield admin: confirmation prompts for destructive actions and copy buttons. */
( function () {
    'use strict';
    document.addEventListener( 'click', function ( event ) {
        var el = event.target.closest ? event.target.closest( '[data-sentinel-confirm]' ) : null;
        if ( el && ! window.confirm( el.getAttribute( 'data-sentinel-confirm' ) ) ) {
            event.preventDefault();
            event.stopPropagation();
        }
    }, true );

    // Copy buttons for command lines.
    document.addEventListener( 'click', function ( event ) {
        var btn = event.target.closest ? event.target.closest( '[data-ss-copy]' ) : null;
        if ( ! btn || ! navigator.clipboard ) {
            return;
        }
        navigator.clipboard.writeText( btn.getAttribute( 'data-ss-copy' ) ).then( function () {
            var label = btn.textContent;
            btn.textContent = '\u2713';
            setTimeout( function () { btn.textContent = label; }, 1500 );
        } );
    } );
}() );
