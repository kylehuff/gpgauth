/* Constants */
GPGAUTH_VERSION = "v1.3.0";
CLIENT_VERSION = "v1.0.3";

// HTTP Headers
SERVER_GPGAUTH_VERSION = 'X-GPGAuth-Version'        /* HTTP Header that reports the gpgAuth server implementation version
                                                       This header is matched against the extension & plugin version for compatability,
                                                       and also serves to advertize server gpgAuth support */
RESOURCE_AUTH_REQUESTED = 'X-GPGAuth-Requested'      /* Used to indicate that the resource has requested gpgAuth authentication */
RESOURCE_AUTH_REQUIRED = 'X-GPGAuth-Required'       /* Used to indicate that the requested resource requires gpgAuth authentication */
SERVICE_LOGIN_URL = 'X-GPGAuth-Login-URL'           /* URL to submit authentication events */
SERVICE_SIGNUP_URL = 'X-GPGAuth-Signup-URL'         /* URL to sign-up for account */
SERVICE_MIGRATION_URL = 'X-GPGAuth-Migration-URL'   /* URL to migrate legacy UN/PW auth to gpgAuth - or to setup gpgAuth for an existing account */
LOGIN_METHOD = 'X-GPGAuth-Method'                   /* POST?, blah, blah */
SERVER_VERIFICATION_URL = 'X-GPGAuth-Verify-URL'    /* URL to perform server verification (must be relative?) */
USER_AUTHENTICATED = 'X-GPGAuth-Authenticated'		/* Header to indicate if the user is currently authenticated */
LOGOUT_URL = 'X-GPGAuth-Logout-URL'					/* URL to perform logout of the user */
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
        chrome.extension.sendRequest({msg: 'enabled'}, function(response) { gpgAuth.init(response); });
    },

    init: function(response) {
        var gpgauth_enabled = response.result.enabled;
        if (gpgauth_enabled == "false" || gpgauth_enabled == false 
            || gpgauth_enabled == ''
            || gpgauth_enabled == null) {
            console.log("gpgauth is not enabled, exiting");
            return false;
            //TODO: Replace this with logic to detect if gpgauth is not enabled, 
            //    and the druid has not yet run - if so, prompt the user to run the druid.
        }
        if (!this.gpg_elements[document.domain]) {
            this.gpg_elements[document.domain] = new Array();
            this.gpg_elements[document.domain]['port'] = (window.location.port != "") ? window.location.port : "80";
        }
        /* Extension has been loaded, make a 'HEAD' request to server for the
           current page to discover if gpgAuth enabled and any related gpgAuth
           requirements */
        var request = new XMLHttpRequest();
        var response_headers = null;

        request.open("HEAD", document.URL, false);
        request.setRequestHeader('X-User-Agent', 'gpgauth-discovery-chrome/1.0.3');
        request.setRequestHeader("Connection", "close")
        request.send(null);
        /* Make the request */
        response_headers = request.getAllResponseHeaders()
        /* Create an object to store any gpgAuth specific headers returned from the server. */
		this.gpgauth_headers = gpgAuth.getHeaders(response_headers)

        this.plugin_loaded = false;
        /* if gpgAuth headers were found, send a message to background.html
            to have it init the plugin */
        if (this.gpgauth_headers.length) {
            chrome.extension.sendRequest({msg: 'show', 'params': { 'domain': document.domain, 'headers': this.gpgauth_headers }}, function(response) {});
            if (this.gpgauth_headers[SERVER_VERIFICATION_URL] != 'invalid') {
                /* do server tests */
                chrome.extension.sendRequest({msg: 'doServerTests', params: {'domain': document.domain, 
                    'server_verify_url': this.gpgauth_headers[SERVER_VERIFICATION_URL],
                    'headers': this.gpgauth_headers,
                    'port' : window.location.port }}, 
                    function(response) { gpgAuth.serverResult(response) });
            }
        } // else listen for an event here

        this.initialized = true;
    },

    serverResult: function(response) {
        if (!response.result['valid']) {
            console.log(response);
        }
        console.log('res 2', response);
        if (response.result['server_validated'] == true || response.result['valid'] == 'override') {
            // the below "stage" check is commented out; I think it is better to assume it is stage0,
            // as this method does nothing otherwise...
            //if (this.gpgauth_headers['X-GPGAuth-Progress'] == 'stage0'){
            	if (this.gpgauth_headers['X-GPGAuth-Requested'] == 'true' || response.result['valid'] == 'override') {
            	//chrome.extension.sendRequest({msg: 'getSelectedTab', params: {}});
            	    port = (document.location.port != "") ? document.location.port : "80";
				    chrome.extension.sendRequest({msg: 'doUserLogin', params: {'domain': document.domain, 
				            'service_login_url': this.gpgauth_headers[SERVICE_LOGIN_URL],
				            'port': port }},
				            function(response) { gpgAuth.login(response) });
		        }
			//}
        }
    },

    login: function(response) {
        if (response.result.valid == true || response.result.valid == 'override') {
            // send the token back..
            var http = new XMLHttpRequest();
            var params = "gpg_auth:keyid=" + encodeURIComponent(response.result.keyid) +
                "&gpg_auth:user_token_result=" + encodeURIComponent(response.result.decrypted_token);
            http.open("POST", this.gpgauth_headers[SERVICE_LOGIN_URL], false);
            http.setRequestHeader('X-User-Agent', 'gpgauth v1.3/chrome');
            http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            http.send(params);
            if(http.readyState == 4 && http.status == 200) {
                this.gpgauth_headers = gpgAuth.getHeaders(http.getAllResponseHeaders());
                chrome.extension.sendRequest({msg: this.gpgauth_headers['X-GPGAuth-Progress'],
                	params: {'domain':document.domain,
		                	'service_login_url': this.gpgauth_headers[SERVICE_LOGIN_URL],
		                	'headers': this.gpgauth_headers,
		                	'result' : response.result}
				});
				gpgAuth.handleRefer(response, this.gpgauth_headers);
            } else {
                console.log(http.getAllResponseHeaders());
                console.log("Status: " + http.status + "<br>Resposne:<br>" + http.responseText);
            }
        }
    },
    
    handleRefer: function(response, headers, domain) {
    	console.log("asked to proceed to page:", response);
    	next = headers['X-GPGAuth-Refer'];
    	if (next && next[0] == "/") {
    		window.location = next;
    	}
    },

	logout: function(response) {
		headers = response.result.validation.headers;
		if (headers[USER_AUTHENTICATED] && headers[LOGOUT_URL] && headers[LOGOUT_URL][0] == "/") {
			window.location = headers[LOGOUT_URL];
		}
	},

    getHeaders: function(response_headers) {
        var gpgauth_headers = { 'length': 0 };
        var re = /(x-gpgauth-.*?): (.*)/gi;
        is_match = false;
        while (is_match != null) {
            is_match = re.exec(response_headers)
            if (is_match) {
                if (is_match[1] == SERVER_VERIFICATION_URL) {
                    if (is_match[2][0] != '/'){
                        /* the verification url points to another server was found
                            we are not going to continue */
                        gpgauth_headers[is_match[1]] = 'invalid';
                        break;
                    }
                }
                gpgauth_headers[is_match[1]] = is_match[2];
                gpgauth_headers.length += 1;
            }
        }
        return gpgauth_headers;
    },

    /*
    Function: listenerUnload
    This function unloads then event listener when the window/tab is closed.
    */
    listenerUnload: function( event ) {
        gpgAuth.initialized = false;
        gpgAuth.status_window.update( "gpgAuth shutting down....", show=false );
        window.removeEventListener( "gpg_auth:login");
    },

};


gpgAuth.onLoad();
