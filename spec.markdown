gpgAuth
-------
Kyle Huff <kylehuff@curetheitch.com>

Aaron C. de Bruyn <aaron@heyaaron.com>

Copyright (c) 1996-2010

gpgAuth: A protocol to seamlessly authenticate users securely using a single non-distributed password.

The spec is seriously out of date now that developemnt has started...  ;)


What is it?
===========
gpgAuth is a process to authenticate users and servers using the exchange of GPG keys.


Assumptions
===========
We assume you are already familiar with the basics of GPG and the exchange of encrypted and/or signed data.
If you are unfailiar, please read the GPG manual at http://gnupg.org/documentation/manuals.en.html


The Problem
===========
There are several problems with the state of authentication on the web.

Usernames: Every site wants a username and/or email, along with a password.  Sometimes you find your username is already taken--so you have to pick a slightly different one.  Over the span of a few months or years, you may forget the username.

Passwords: You are supposed to be using a password of at least 6 (if not 8) characters minimum.  You are also supposed to use a different password at every website.  How many accounts do you have online?  5? 20? 100?  Do you have trouble memorizing the output of 'pwgen -cnsy'?  Most people at some point begin to use one password on multiple systems.  Maybe one password for banking related sites, and another for social networking, and maybe a third for work.  Or maybe you develop a system where your Facebook password is 'facebook123!' and Twitter is 'twitter123!'.  Not very secure.  It's not human nature to memorize hundreds of characters of stuff that looks vaguely like line noise.  Worst still, most banks have several layers of challenge questions.

E-Mail Addresses: Everyone has an e-mail address.  Most everyone remembers their e-mail address.  Wouldn't it be easy if this is all it required to sign in everywhere?


The Solution (summary)
======================
You give your e-mail address or username and GPG public key to a website when signing up.  The website gives you its public key.

Logging in consists of putting in your e-mail address or username and clicking submit.

Step 1
------
The website sends grabs your username, looks it up in its database and finds your associated public key.  The website then generates a random blob of data, signs it with it's private key, and then encrypts it to your public key.  The resulting token is then sent to your browser.

Step 2
------
Your browser receives the token, and is able to decrypt it with your private key.  It then verifies the signature on the random blob of data to ensure it really came from the correct server.  Your browser then signs that blob of data with its private key and encrypts it back to the servers public key.  The token is then sent back to the server.

Step 3
------
The server receives the token, and is able to decrypt it with its private key.  The user signature is then verified and the blob is compared to the original blob sent at the beginning of the authentication cycle.

The Result
----------
If all three steps succeed, the server has authenticated to the user and the user has been authenticated to the server.


How it Works (detailed)
=======================
The web page needs a form for the placement of the client token.
Here is an example form:

    <form id="gpg_auth:login_form" method="post" action="javascript: emit_event();document.forms[0].action='?stage=2';document.forms[0].submit();">
      <span>Enter your user ID: </span><input id="gpg_auth:username" name="username" width="10" size="10" autocomplete="off" action="alert('123');"/>
      <input type="button" value="Submit" onClick="emit_event(); submit()"/>
      <input type="text" id="gpg_auth:version" value="v1.2.2" style="display:none;"/>
      <input type="text" id="gpg_auth:server_token" name="gpg_auth:server_token" value="" style="display:none;"/>
    </form>


The web page should start the process by emitting a 'gpg_auth:login' event.

    var ev = document.createEvent("Events");
    ev.initEvent("gpg_auth:login", true, false);
    document.dispatchEvent(ev);



Lets signup for an account with a fictional service we will call "A":

You do banking with service A, and you trust they are who they say they are, (or why would you bank with them?). You have obtained their Public Key and imported it into your Keyring (A storage container for Public and Private Keys), and you have chosen to trust that Public Key.

To signup for an account, you provide them a username, and your Public Key. Once your account is active, you can log in with the following steps:

You go to their login page and provide your username and a token of random data that you have encrypted to their Public Key. At this point service A decrypts the chunk of data you gave them, and immediately encrypts a NEW token to your Public Key and gives you back the unencrypted token you gave them, along with the new token the service has encrypted to your Public Key.

When you receive the encrypted and unencrypted tokens, you must first verify the server has correctly decrypted the token you provided, the contents should match the data you encrypted to their Public Key, and then you must decrypt the encrypted token you received and hand it back to the server.

So that means, because you encrypted data to them with their Public Key, that they successfully decrypted and returned to you (you verified it matches), you have verified that they are the owner of the Public Key, and likewise, they have verified that you have the ability to decrypt the token they have encrypted to your Public Key. Bam! symmetric web authentication.

So you may ask, why? What is wrong with using SSL to verify the identiy of the site and just use the username/password scheme?

What's wrong with web authentication today
------------------------------------------

The Conventional Login scheme is usually composed of the Service Provider back-end (the data storage), and a user front-end (authentication system), where the user, upon account creation is assigned a username and a password. This username/password combination is the gateway to whatever data the service provides.

Okay, so lets look at this, conventional login. What is wrong with it?

Here lets look at both sides of the spectrum; what is wrong with it for the service provider, but most importantly, what is wrong with for the user

* Users Service Provider Susceptible to "Phishing" Overhead Theft Theft Keyloggers Liability Social Engineering Non-uniform across providers Repetitious Stale Authentication Weak Authentication Hassle That is quite a list, let me explain why I think those are all problems

* "Phishing" - Just about everyone knows about "Phishing" - The un-suspecting user arrives at website designed to look and feel just like the official website of the service the user has an account with. There are really two facets of compromise that the "Phishers" are attempting with this method; the first is to get user to type in their login information into the "Phishers" login screen so the "Phishers" can use the users login credentials to gain access to the users account on the official website. The second is to get the user to believe that they have signed into the official website, at which point the "Phishers" ask the user to update sensitive information like their social security number or credit card information.

* Theft - Theft can happen on both sides of the spectrum, both the user side and the service provider side.

The typical user stores login information in a format that is easy to retrieve, i.e., on index cards, or in text files on the computer, or saved in the browser.

On the service provider side, an attacker can obtain your login information by gaining access to the authentication database at the service provider. This is often negated by the provider implementing encryption of stored passwords, however, even with encryption, some services with a large user-base feel the need to be able to decrypt the stored passwords to distribute to the user on request when they call in, a convenience for the user because the user can't remember.

* Keyloggers - The goal of a keylogger is to catch the keystrokes of the users as they type in their username and password into the service provider(s) website. This is most often accomplished by a virus/trojan. Needless to say, it is bad.

Now, this method is also multi-faceted; To gain login credentials as well as sensitive information.

I am only speaking about authentication here, and the problems associated with conventional login methods. Keyloggers are not dangerous only to authentication, but I am only speaking in the context of authentication.

* Social Engineering - With some service providers, if you call in to retrieve your password, you must first sacrifice your first-born, eat three cans of spinach, provide a subset of your DNA, list your blood-type, entire family tree and pay a $20 service charge with the same credit card used to sign-up.. Don't get me wrong, it is good that the service provider is attempting to protect me against the world wide web authentication joke, but what a hassle. On the flip side, there are some providers that will just hand that out to whoever has the account number. The middle ground is providers who will only give that information out after verifying the last four digits of the users social security number, and possibly some other items of personal information. This seems to be a happy medium for most users and providers, the trouble is, one of the hottest crimes at the time of this writing is Identity Theft. The information required, such as the last four of the users social security number, home address or mothers maiden name, are used quite frequently both online and offline.

* Non-uniformity - The problem is, I have an online account with about 30 different providers, ranging from email accounts to banking websites. What is my username again? What is my password? For many users this is an un-mitigated nightmare that drives them to writing this type of information down, which is obtainable without too much effort if you know anything about the user.

The issue of lacking username synergy across providers has been argued to not be a legitimate gripe with current web authentication, because it provides security through obscurity. I may know your username for service A, but that is not necessarily the same for service B. Let me just say that security through obscurity is in my opinion, not security at all, it is nothing more than obscurity. Obscurity is not an enforceable, audit-able measure of protection. You can't run diagnostics on obscurity. You can't test obscurity. The problem with obscurity is that is it too damn obscure..

* Repetition - Due to the problems associated with users having different usernames at different services, to help cope, users often use the same password at all the various services. If I know you always use a certain password, and that you have accounts with service A and service B, depending on the service, I can usually retrieve the username through an option on the website or by calling the provider and pretending to be you.. All I need to do is get some personal information first, which is apparently not very difficult. If it was difficult, I don't imagine Identity Theft would be that big of a problem.

* Stale Authentication - Okay, I have an account with service A and service B, I am a good user and I use different passwords at each of those services. Problem is, when was the last time I changed the password? If I have been using the same password for the last 3 years, there is a heightened chance that somewhere along the line I was either careless with keeping that a secret, or I've been subject to a keylogger, or phishing.

* Weak Authentication - The trend for most users is to create passwords that make sense to them, i.e., they are not hard to guess. It is pretty amazing how many passwords I've run into that are something simple, like a devout fisherman using "fish" or "salmon". Something that is a part of their everyday lives so they don't forget. So if I know much about you, it might not be hard to guess your password.

* Hassle - This last one is a problem, take a poll of people around you and ask them how many passwords they have. While your at it, ask them when the last time they changed those passwords. The frustration associated with the entire convoluted process causes the user to (unwittingly) compromise security by making the process simpler for them. Another drawback is the lack of trust instilled in the system and processes. While it is good to not trust system that has so many issues, that lack of trust can hinder progress, productivity and peace of mind.

Okay, whew, what a giant pile of crap. I find it amazing that what is wrong with web authentication today is accepted as "the norm". This is how web authentication has worked for as far back as I've been using the web. So we have looked at what is wrong, what does gpgAuth do about it?

Lets go through the steps of the gpgAuth authentication process, and look at what is happening, and how each of those steps address some of the issues we just went through.

1. The user generates an encrypted token of random data (encrypted to the service's Public Key), and stores the unencrypted version locally.
2. That encrypted token is sent to the server with the username of the associated account.
3. The server checks to see if the username exists, if it does, it retrieves the Fingerprint of the associated Public Key.
4. The server checks to see if the Public Key has been revoked.
5. The server generates an encrypted token of random data (encrypted to the users Public Key), and stores the unencrypted version locally.
6. The server sends the unencrypted user token, and the encrypted server token to the user.
7. At this point the user receives the decrypted token back, and checks to make sure it matches the originally encrypted data.
8. If the client is satisfied the server has authenticated, it decrypts the encrypted server token received and sends it to the server.
9. The server compares the un-ecrypted text sent from the client to make sure it matches. If the server is satisfied, the authentication is completed.

Step 1 - 7: Service Verification These steps are designed to help mitigate website spoofing or "Phishing" sites. When the client chooses the Public Key to encrypt the token to, instead of the server informing the client which Public Key to use, the Public Key is referenced explicitly by the key UID, which should match the base domain name exactly. For example, if you signed up for service with provider A, when they provided their Public Key, one of the factors in establishing whether to trust the key or not in the future is predicated on the key UID matching the domain, in this case, providerA.com. That way, if for some reason you end up at prov1derA.com (mis-spelled), there is no corresponding key in your Keyring, therefor the site cannot be verified.

Step 8 - 9: User Verification These steps are for proving to the service that the requested party is in fact in possession of the Private Key associated with the Public Key on the account, and they have the Passphrase to use the Private Key.

So lets look at which of the Web Authentication Issues listed above that we are attempting to address with this new method of web authentication;

* Phishing - Handled by referencing Public Keys to encrypt the server token with by UID which matches the FQDN of the service, and verified by the service's ability to decrypt the token encrypted with the selected Public Key.

* Social Engineering - If you call the service provider, they can't tell you your username and password, THEY DON'T HAVE IT! The password is simply randomly generated data that is encrypted to your Public Key. The only way to decrypt that token is to have possession of your Private Key and it's associated Passphrase. I might know your name, date of birth and mothers maiden name, but that won't get me your password.

* Repetition - The fact that you are using the same login credentials for 30 different providers is not as much of an issue if keep your Private Key and associated Passphrase safe. Your Private Key Passphrase is the only password you must remember. It is far less likely users will write it down in fear of forgetting, and it is not ever used out on the Net, it is used locally where you encrypt/decrypt and sign data.

* Non-uniformity - If you chose to use the same Public/Private Keypair for every provider, you now have some symmetry across providers. Now, granted, in the model described above it still uses a username, or common name to reference the account, which is not exactly unique. You could quite feasibly use some other piece of unique data, like your Public Key Fingerprint, which is a unique ID for your Public Key.

* Stale Authentication - When was the last time you changed your password with provider I, X, O, Y and E? If you change your Private Key Passphrase on your machine, it is changed everywhere essentially. Because you only use the Passphrase locally, no-one ever needs (or should) have your Passphrase. With some best practices, and some techniques that we hope to show you later, you can set your Keypair to Expire.

* Weak Authentication - There is nothing weak about Public/Private Key Authentication. The weakest link is going to be how well you guard your Private Key, and associated Passphrase.

* Hassle - The described process above in the context of actually logging in is an extreme hassle. I will get to what we have worked out to mitigate that hassle (see here), but let us be fair, the hassle listed among the negates earlier was in reference to Account Management, and how it is a nightmare for the user. That, indeed goes away. One sign-in, if you chose, everywhere.

* Theft - This was a multifaceted problem, primarily, the problem of people hijacking information from the service provider about your account. I said it before, THEY DON'T HAVE IT! They have your Public Key, and by definition, it is PUBLIC.. It is not unsafe for someone to have your Public Key. You can retrieve Public Keys by the thousands from a globally available Key Server (which is a repository of Public Keys on the internet). Now, theft is still a problem if you do not guard your Private Key, and it's associated Passphrase. However, neither of those should ever be used out on the web/network. Those are for local functions, and should remain local and protected.

* Keyloggers - This one is still essentially an issue, but not in the same way. Someone can steal your Passphrase through a keylogger, but they can't steal your Private Key with a keylogger ( unless you type your Private Key, which is not only strangely stupid, it is very time consuming. )

* Other Benefits: Security is in the users hands, not solely the provider. With symmetric authentication, the Provider is verified against your Trusted Keys, and the user is authenticated with their Trusted Keys.

If you believe your Private Key has been compromised, you now the ability to revoke access to accounts with that Keypair by uploading a revocation certificate to the Key Server. What is gpgAuth and how does it work
