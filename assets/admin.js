/* Sentinel Shield admin: confirmation prompts for destructive actions. */
( function () {
    'use strict';
    document.addEventListener( 'click', function ( event ) {
        var el = event.target.closest ? event.target.closest( '[data-sentinel-confirm]' ) : null;
        if ( el && ! window.confirm( el.getAttribute( 'data-sentinel-confirm' ) ) ) {
            event.preventDefault();
            event.stopPropagation();
        }
    }, true );
}() );
