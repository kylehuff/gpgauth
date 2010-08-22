/* Constants */
GPGAUTH_VERSION = "v1.3.0";
CLIENT_VERSION = "v1.3.0";

// HTTP Headers
SERVER_GPGAUTH_VERSION = 'X-GPGAuth-Version'        /* HTTP Header that reports the gpgAuth server implementation version
                                                       This header is matched against the extension & plugin version for compatability,
                                                       and also serves to advertize server gpgAuth support */
RESOURCE_AUTH_REQUIRED = 'X-GPGAuth-Requested'      /* Used to indicate that the requested resource has requested gpgAuth authentication */
RESOURCE_AUTH_REQUIRED = 'X-GPGAuth-Required'       /* Used to indicate that the requested resource requires gpgAuth authentication */
SERVICE_LOGIN_URL = 'X-GPGAuth-Login-URL'           /* URL to submit authentication events */
SERVICE_SIGNUP_URL = 'X-GPGAuth-Signup-URL'         /* URL to sign-up for account */
SERVICE_MIGRATION_URL = 'X-GPGAuth-Migration-URL'   /* URL to migrate legacy UN/PW auth to gpgAuth - or to setup gpgAuth for an existing account */
LOGIN_METHOD = 'X-GPGAuth-Method'                   /* POST?, blah, blah */
SERVER_VERIFICATION_URL = 'X-GPGAuth-Verify-URL'    /* URL to perform server verification (must be relative?) */
/* End Constants */


/*
   Class: gpgAuth
   This class implements gpgAuth
*/
var gpgAuth = {

    /*
    Function: onLoad
    This function is called when a new chrome window is created. It sets the GPG preferences and
    tests the server for gpgAuth support and checks if it passes validation.
    */
    onLoad: function() {
        this._version = CLIENT_VERSION;
        if (!this.gpg_elements) {
            this.gpg_elements = new Array();
        }
        var gpgauth_enabled = true;
        if (!this.gpg_elements[document.domain]) {
            this.gpg_elements[document.domain] = new Array();
        }
        /* Extension has been loaded, make a 'HEAD' request to server for the
           current page to discover if gpgAuth enabled, and any related gpgAuth
           requirements */
        var request = new XMLHttpRequest();
        var response_headers = null;

        request.open("head", document.URL, false);
        request.setRequestHeader('X-User-Agent', 'gpgauth-discovery-chrome/1.3');
        request.send(null);
        /* Make the request */
        response_headers = request.getAllResponseHeaders()
        
        /* Create an object to store any gpgAuth specific headers returned from the server. */
        //TODO: this should be a function, which returns the object.
        this.gpgauth_headers = {'length': 0};
        var re = /(x-gpgauth-.*?): (.*)/gi;
        is_match = false;
        while (is_match != null) {
            is_match = re.exec(response_headers)
            if (is_match) {
                if (is_match[1] == SERVER_VERIFICATION_URL) {
                    if (is_match[2][0] != '/'){
                        /* the verification url points to another server was found
                            we are not going to continue */
                        this.gpgauth_headers[is_match[1]] = 'invalid';
                        break;
                    }
                }
                this.gpgauth_headers[is_match[1]] = is_match[2];
                this.gpgauth_headers.length += 1;
            }
        }

        this.plugin_loaded = false;
        /* if gpgAuth headers were found, send a message to background.html
            to have it init the plugin */
        if (this.gpgauth_headers.length) {
            chrome.extension.sendRequest({msg: 'show'}, function(response) {});
            if (!this.gpg_elements[document.domain]['server_verified']) {
                if (this.gpgauth_headers[SERVER_VERIFICATION_URL] != 'invalid') {
                    /* do server tests */
                    chrome.extension.sendRequest({msg: 'doServerTests', params: {'domain':document.domain, 
                        'server_verify_url': this.gpgauth_headers[SERVER_VERIFICATION_URL],
                        'headers': this.gpgauth_headers }}, 
                        function(response) { gpgAuth.serverResult(response) });
                }
            } else {
                console.log('not checking server again, already done');
            }
        }
        //TODO: maybe a check of the version and update here ??

        this.status_window = gpgauth_status;
        this.status_window.onLoad();
        if (gpgauth_enabled) {
            if (!this.initialized) {
                this.status_window.update("gpgAuth " + this._version + " Initialized..", show=false);
            }
        }

        if ( this.gpgauth_statusbar_enabled ) {
            this.status_window.showIcon();
        }
        this.initialized = true;
    },

    serverResult: function(response) {
        if (!response.result['valid']) {
            console.log(response.result);
        }
        if (response.result['server_validated'] == true) {
            x = document.createElement('pre');
            console.log(this.gpgauth_headers);
            document.body.appendChild(x); x.innerText = "cached server validation: " + response.result.cached;
            if (this.gpgauth_headers['X-GPGAuth-Progress'] == 'stage0'){
                console.log("calling doUserLogin");
                chrome.extension.sendRequest({msg: 'doUserLogin', params: {'domain':document.domain, 
                        'service_login_url': this.gpgauth_headers[SERVICE_LOGIN_URL]}},
                        function(response) { gpgAuth.login(response) });
            }
        }
    },

    login: function(response) {
        if (response.result.valid == true) {
            // send the token back..
            console.log("send the token back..");
            login_form = document.createElement('form');
            login_form.method = "POST";
            login_form.action = this.gpgauth_headers[SERVICE_LOGIN_URL];
            keyid_field = document.createElement('input');
            token_field = document.createElement('input');
            keyid_field.type = "text";
            token_field.type = "text";
            keyid_field.name = "gpg_auth:keyid";
            token_field.name = "gpg_auth:user_token_result";
            keyid_field.setAttribute('value', response.result.keyid);
            token_field.setAttribute('value', response.result.decrypted_token);
            login_form.appendChild(keyid_field);
            login_form.appendChild(token_field);
            document.body.appendChild(login_form);
            login_form.submit();
            console.log(this.gpgauth_headers[SERVICE_LOGIN_URL]);
        }
    },

    /*
    Function: listenerUnload
    This function unloads then event listener when the window/tab is closed.
    */
    listenerUnload: function( event ) {
        gpgAuth.initialized = false;
        gpgAuth.status_window.update( "gpgAuth shutting down....", show=false );
        window.removeEventListener( "gpg_auth:login", this.login, false, true );
    },

    gpgauthDialog: function ( message_type, error_message, details, check_text ) {
        icon = ""; // Set the icon to nothing initially
        if ( message_type == "warning" ) {
            var title = "gpgAuth: Warning";
            var icon = "chrome://firegpg/skin/Warning.png";
        } else if ( message_type == "error" ) {
            var title = "gpgAuth: Error";
            var icon = "chrome://firegpg/skin/Error.png";
        } else {
            var title = "gpgAuth: Message";
            var icon = "chrome://firegpg/skin/Question.png";
        }

        var params = { pin: { icon: icon, dialog_title: title, dialog_message: error_message, dialog_details: details, checkbox_text: check_text}, pout: false };
        window.openDialog( "chrome://gpgauth/gpgauth_dialog.xul", "gpgauthDialog", "chrome, dialog, modal, centerscreen", params ).focus();
        return params.pout;
    }
};

var gpgauth_status = {
  _initialized: false,
  _statusButton: undefined,
  _panel: undefined,
  _menu: undefined,

  pref: undefined,

  onLoad: function() {
    if (this._initialized){
        return;
    }
    this._initialized = true;
    this._statusButton = document.getElementById("gpgauth-statusbar-button");
    this._panel = document.getElementById("gpgauth-Panel");
    this._menu = document.getElementById("gpgauth-menu-popup");
  },

  onUnload: function() {
  },

  togglePopup: function() {
    if (this._panel.state == "open"){
              this._panel.hidePopup();
        gpgauth_status._panel.hidden = true;
     }else {
      var f = function(){
        gpgauth_status._panel.hidden = false;
        gpgauth_status._panel.openPopup(gpgauth_status._statusButton.parentNode, "before_end", 0, 0, false, false);
      }
      f();
    }
  },

  showIcon: function() {
    this._statusButton.style.display = '';
  },

  _gel: function(id){
        return document.getElementById(id);
  },

  scrollToEnd: function( element ) {
    var tBox = element;

    // current selection postions
    var startPos = tBox.textLength;
    var endPos = tBox.textLength;

    // set start and end same (to start)
    tBox.selectionStart = startPos;
    tBox.selectionEnd = startPos;

    // insert character
    ev = document.createEvent("KeyboardEvent");
    ev.initKeyEvent('keypress', true, true, window, false, false, false, false, 0, 1);
    tBox.inputField.dispatchEvent(ev); // causes the scrolling

    // remove character
    ev = document.createEvent("KeyboardEvent");
    ev.initKeyEvent('keypress', true, true, window, false, false, false, false, 8, 1);
    tBox.inputField.dispatchEvent(ev); // "backspace" to remove

    // reset selection
    tBox.selectionStart = startPos;
    tBox.selectionEnd = endPos;
  },

  cancelInput: function( event, element ) {
    var tBox = element;
    ev = document.createEvent("KeyboardEvent");
    ev.initKeyEvent('keypress', true, true, window, false, false, false, false, 8, 1);
    tBox.inputField.dispatchEvent(ev); // "backspace" to remove

  },

  update: function(value, show) {
    return false;
    if (show==null){
        show = true;
    }
    if (value==null){
        value = '123';
    };
    var padDigits = function( digits ) { return digits.toString().length == 2 ? digits.toString() : "0" + digits.toString(); }
    var timestamp = new Date();
    timestamp = padDigits(timestamp.getHours()) + ":" + padDigits(timestamp.getMinutes()) + ":" + padDigits(timestamp.getSeconds());
    textbox = document.getElementById( "gpgauth-Status-details" );
    textbox.value += timestamp + "  " + value + "\n";
    try {
        gpgauth_status.scrollToEnd( textbox );
    } catch(err) {
        //do nothing
    }
    if ( gpgAuth.gpgauth_statuswindow_enabled && show ) {
        if ( gpgauth_status._panel.hidden ) {
            gpgauth_status._panel.hidden = false;
            gpgauth_status._panel.openPopup(gpgauth_status._statusButton.parentNode, "before_end", 0, 0, false, false);
        }
    }
  },

};

gpgAuth.onLoad();
