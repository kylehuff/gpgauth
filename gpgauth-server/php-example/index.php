<?php
//start the session 
session_start();
header('X-GPGAuth-Version: 1.3.0');
header('X-GPGAuth-Requested: false');
// The following headers describe to the client where to look for resources;
// The way this example PHP page actually operates, the '?page' are just for 
// differentiating the requests while debugging/testing - the only page that requires
// a "?page" querystring variable in this example is the logout page.
// All of these paths must be relative to the root of the domain. Nothing else will
// be permitted by the client.
header('X-GPGAuth-Verify-URL: /tests/php/index.php?server_verify');
header('X-GPGAuth-Login-URL: /tests/php/index.php?login');
header('X-GPGAuth-Logout-URL: /tests/php/index.php?logout');
// This points to an ACII armored public key (can be multiple keys in one file)
// that is used to allow the client to import the servers pubic key.
header('X-GPGAuth-Pubkey-URL: /tests/gpgauth.org.pub');
$CURRENT_PAGE = "gpgAuth Authentication tests start";
$PAGE_CONTENT = "This page advertises the gpgAuth headers";

// Database Variables
$dbHost = "AVALIDHOST";
$dbUser = "AVALIDUSER";
$dbPass = "AVALIDPASS";
$dbDatabase = "AVALIDDB";

// This should point to a path accessible by the user the web instance is
// running under. (www-data in this example)
putenv('GNUPGHOME=/var/www/gpgauth.org/.gnupg');

// create new GnuPG object
$gpg = new gnupg();
// throw exception if error occurs
$gpg->seterrormode(gnupg::ERROR_EXCEPTION); 

// If the user does not have a validated session, begin processing
if(!session_is_registered($_SESSION['keyid'])){
	header('X-GPGAuth-Progress: stage0');
	header('X-GPGAuth-Authenticated: false');
	
	// This variable controls the "Auto login" functionality;
	// by default, this test page will automatically attempt to login
	// unless the user has landed on the logout page, or if the parameter
	// "no_auto_login" has been appended to the querystring.
	$request_gpgauth = "true";
	foreach ($_GET as $key => $value) {
		if ($key == "no_auto_login") {
			$request_gpgauth = "false";
		}
	}
	foreach ($_GET as $key => $value) {
		if ($key == "logout") {
			$request_gpgauth = "false";
		}
	}
	// Set the Auth-Requested header to what we determined above
	header('X-GPGAuth-Requested: ' . $request_gpgauth);
	
	// The user has requested the server to verify itself
	if ($_POST['gpg_auth:server_verify_token']) {
		$CURRENT_PAGE = "Server Verification Test";

		// specify the recipient to force decryption with a given key
		$recipient = "cti.localhost";

		$ciphertext = $_POST['gpg_auth:server_verify_token'];

		try {
		  $gpg->adddecryptkey($recipient, '');
		  $plaintext = $gpg->decrypt($ciphertext);
		  $server_response = $plaintext;
		  header('X-GPGAuth-Verify-Response: ' . $plaintext);
		} catch (Exception $e) {
		  header('X-GPGAuth-Error: true');
		  header('X-GPGAuth-Verify-Response: ' . $e->getMessage());
		}
	} elseif ($_POST['gpg_auth:keyid']) {
		if (!$_POST['gpg_auth:user_token_result']) {
			header('X-GPGAuth-Progress: stage1');
			$keyid = $_POST['gpg_auth:keyid'];

			// specify the recipient to encrypt with the key-id provided by the user
			$recipient = $keyid;

			// generate a random token to encrypt
			$nonce = md5(uniqid(mt_rand(), true));
			
			/* next we wrap the token in the defined header. The header serves as a check to ensure
			   that someone is not passing it encrypted data it does not want to decrypt and
			   send back. Data encrypted by the user for other purposes (privacy) are not
			   contained in this header.
			
			   A valid header consists of a 4 sections,
			   1. gpgauthv{VERSION}
			   2. the length of the decrypted version of the token
			   3. the decrypted token
			   4. again, gpgauthv{VERSION}
			
			*/
			$plaintext = "gpgauthv1.3.0|" . strlen($nonce) . "|" . $nonce . "|gpgauthv1.3.0";

			// attempt to encrypt it to the user, or return any failure.
			try {
			  $gpg->addencryptkey($recipient);
			  $ciphertext = $gpg->encrypt($plaintext);
			  $server_response = $token;
			  // This header holds the encrypted token that is passed to the client
			  header('X-GPGAuth-User-Auth-Token: ' . quotemeta(urlencode($ciphertext)));
			} catch (Exception $e) {
			  header('X-GPGAuth-Error: true');
			  header('X-GPGAuth-User-Auth-Token: ' . $e->getMessage());
			}
			/*
			  Connect to the user database and update the user_token we generated for that user.
			  When the client returns the decrypted token, we will test it for a match against
			  this database field.
			*/
			$db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database."); 
			mysql_select_db("$dbDatabase", $db) or die ("Unable to select the database.");
			mysql_query("UPDATE users SET user_token = '$plaintext' WHERE INSTR(fingerprint, '$keyid')");
			mysql_close($db);
		} else {
			/* We have received BOTH a user key-id and the decrypted version of the token we 
			   previously provided to the client, so either A.) The client has verified the
			   identity of our server, or B.) They have elected to proceed anyway.
			*/
			header('X-GPGAuth-Progress: stage2');
			$keyid = $_POST['gpg_auth:keyid'];
			$token = $_POST['gpg_auth:user_token_result'];
			$db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
			mysql_select_db("$dbDatabase", $db) or die ("Unable to select the database.");
			// Query the database to see if the decrypted token provided by the user matches the token we
			// generated for that user.
			$result = mysql_query("SELECT username, fingerprint, user_token FROM users WHERE INSTR(fingerprint, '$keyid') AND user_token = '$token'");
			$row = mysql_fetch_row($result);
			mysql_close($db);
			// There is a match, the user is logged in; time to setup the variables
			if ($row) {
				header('X-GPGAuth-Progress: complete');
				header('X-GPGAuth-Authenticated: true');
				// This is an optional header value which will redirect the user to
				// the specified page.
				header('X-GPGAuth-Refer: /tests/php/index.php');
				session_start();
				// Register the session
				session_register($keyid);
				$_SESSION['keyid'] = $keyid;
				$CURRENT_PAGE = "User Verification Test Completed";
				$PAGE_CONTENT = "You have been successfully authenticated using gpgAuth.";
			} else {
				header('X-GPGAuth-Authenticated: false');
				$CURRENT_PAGE = "User Verification Test Failed";
				$PAGE_CONTENT = "Unable to find match in database";
			}
		}
	}
} else {
	// The user already has a registered session
	header('X-GPGAuth-Authenticated: true');
	$CURRENT_PAGE = "Server Verification Test Completed";
	$PAGE_CONTENT = "You are currently logged in; Click here to <a href=\"/tests/php/index.php?logout\">logout</a><br/>";
	// if the "logout" parameter is detected in the query-string, we should do that.
	foreach ( $_GET as $key => $value ) {
		if ($key == "logout") {
			header('X-GPGAuth-Authenticated: false');
			header('X-GPGAuth-Requested: false');
			//session variable is registered and the user is ready to logout 
			session_unset();
			session_destroy();
			$CURRENT_PAGE = "Server Logout Complete";
			$PAGE_CONTENT =  "You have been successfully logged out; if you would like to log back in, <a href=\"/tests/php/index.php?login\">click here</a>";
		}
	}
}
?>
<html>
<head>
<title><? echo $CURRENT_PAGE ?></title>
</head>
<body>
<p><? echo $PAGE_CONTENT ?></p>
</body>
</html>
