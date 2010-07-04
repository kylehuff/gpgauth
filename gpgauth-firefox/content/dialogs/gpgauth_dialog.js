function onLoad() {
	// Use the arguments passed to us by the caller
	document.title = window.arguments[0].pin.dialog_title;
	document.getElementById( "gpgauthDialog-icon" ).style.listStyleImage = "url( '" + window.arguments[0].pin.icon + "' )";
	document.getElementById( "gpgauthDialog-message" ).value = window.arguments[0].pin.dialog_message;
	if ( window.arguments[0].pin.dialog_details ) {
		document.getElementById( "gpgauthDialog-details" ).value = '(' + window.arguments[0].pin.dialog_details + ')';
	} else {
		document.getElementById( "gpgauthDialog-details" ).style.display = 'none';
	}
	if ( !window.arguments[0].pin.checkbox_text ) {
		document.getElementById( "gpgauthDialog-CheckBox" ).style.visibility = 'hidden';
	} else {
		document.getElementById( "gpgauthDialog-check" ).setAttribute( 'label', window.arguments[0].pin.checkbox_text );
	}
}

function onReturn() {
	window.arguments[0].pout = { accept: true, check: document.getElementById( "gpgauthDialog-check" ).checked };
}
