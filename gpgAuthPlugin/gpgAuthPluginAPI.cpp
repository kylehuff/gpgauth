#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"

#include "gpgAuthPluginAPI.h"
#include "keyedit.h"


/* 
 * Define non-member methods/inlines
 */

#define errstr "{ \n\
    \"error\": \"true\" \n\
    \"method\": \"%s\", \n\
    \"gpg_error_code\" : \"%d\", \n\
    \"error_string\": \"%s\", \n\
    \"line\": \"%d\", \n\
    \"file\": \"%s\" \n}"

#ifdef HAVE_W32_SYSTEM
#define __func__ __FUNCTION__
#endif

std::string
vformat (const char *fmt, va_list ap)
{
    // Allocate a buffer on the stack that's big enough for us almost
    // all the time.  Be prepared to allocate dynamically if it doesn't fit.
    size_t size = 1024;
    char stackbuf[1024];
    std::vector<char> dynamicbuf;
    char *buf = &stackbuf[0];

    while (1) {
        // Try to vsnprintf into our buffer.
        int needed = vsnprintf (buf, size, fmt, ap);
        // NB. C99 (which modern Linux and OS X follow) says vsnprintf
        // failure returns the length it would have needed.  But older
        // glibc and current Windows return -1 for failure, i.e., not
        // telling us how much was needed.

        if (needed <= (int)size && needed >= 0) {
            // It fit fine so we're done.
            return std::string (buf, (size_t) needed);
        }

        // vsnprintf reported that it wanted to write more characters
        // than we allotted.  So try again using a dynamic buffer.  This
        // doesn't happen very often if we chose our initial size well.
        size = (needed > 0) ? (needed+1) : (size*2);
        dynamicbuf.resize (size);
        buf = &dynamicbuf[0];
    }
}

class json_string {
private:
  std::string text;
public:
    std::string format(char *fmt, ...) {
        va_list ap;
        va_start (ap, fmt);
        std::string buf = vformat (fmt, ap);
        va_end (ap);
        return buf;
    }
};

/* An inline method to convert a null char */
inline
static const char *
    nonnull (const char *s)
    {
      return s? s :"[none]";
    }

/* An inline method to convert an integer to a string */
inline
std::string i_to_str(const int &number)
{
   std::ostringstream oss;
   oss << number;
   return oss.str();
}

/* An inline method to escape single and double quotes 
    from the passed string object */
inline
void sanitize (std::string& str)
    {
    for (unsigned int i = 0; i < str.length(); i++)
    {
      if (str[i] =='\'' || str[i]=='\"')
      {
        str.replace (i,1,"\\\\'");
        i += 3;
      }
    }
}

gpgAuthPluginAPI::gpgAuthPluginAPI(gpgAuthPluginPtr plugin, FB::BrowserHostPtr host) : m_plugin(plugin), m_host(host)
{
    registerMethod("getPublicKeyList", make_method(this, &gpgAuthPluginAPI::getKeyList));
    registerMethod("getPrivateKeyList", make_method(this, &gpgAuthPluginAPI::getPrivateKeyList));
    registerMethod("getDomainKey", make_method(this, &gpgAuthPluginAPI::getDomainKey));
    registerMethod("verifyDomainKey", make_method(this, &gpgAuthPluginAPI::verifyDomainKey));
    registerMethod("gpgEncrypt", make_method(this, &gpgAuthPluginAPI::gpgEncrypt));
    registerMethod("gpgDecrypt", make_method(this, &gpgAuthPluginAPI::gpgDecrypt));
    registerMethod("gpgSignUID", make_method(this, &gpgAuthPluginAPI::gpgSignUID));
    registerMethod("gpgEnableKey", make_method(this, &gpgAuthPluginAPI::gpgEnableKey));
    registerMethod("gpgDisableKey", make_method(this, &gpgAuthPluginAPI::gpgDisableKey));
    registerMethod("gpgDeleteUIDSign", make_method(this, &gpgAuthPluginAPI::gpgDeleteUIDSign));
    registerMethod("gpgGenKey", make_method(this, &gpgAuthPluginAPI::gpgGenKey));
    registerMethod("gpgImportKey", make_method(this, &gpgAuthPluginAPI::gpgImportKey));

    registerEvent("onkeygenprogress");
    registerEvent("onkeygencomplete");

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &gpgAuthPluginAPI::get_version));
    registerProperty("gpgconf_detected",
                     make_property(this,
                        &gpgAuthPluginAPI::gpgconf_detected));
}

gpgAuthPluginAPI::~gpgAuthPluginAPI()
{
}

gpgAuthPluginPtr gpgAuthPluginAPI::getPlugin()
{
    gpgAuthPluginPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}

gpgme_ctx_t gpgAuthPluginAPI::init(){
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    std::string cfg_present;
    /* Initialize the locale environment.
     * The function `gpgme_check_version` must be called before any other
     * function in the library, because it initializes the thread support
     * subsystem in GPGME. (from the info page) */  
    gpgAuthPluginAPI::_gpgme_version = (char *) gpgme_check_version(NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    #ifdef LC_MESSAGES
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif
    err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);

    err = gpgme_new (&ctx);
    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);

    gpgAuthPluginAPI::is_initted = 1;

    return ctx;
};


/*
    This method executes gpgauth.getKeyList with an empty string which
        returns all keys in the keyring.
*/
std::string gpgAuthPluginAPI::getKeyList(const std::string& domain, int secret_only){
    /* declare variables */
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_keylist_result_t result;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
    gpgme_subkey_t subkey;

    /* initiate a new instance (context) of gpgme and
        assign it to ctx, catch any gpgme_error */
    //gpgme_error_t err = gpgme_new (&ctx);
    //if(err != GPG_ERR_NO_ERROR) return "error: 1; Unable to init new gpgme context";

    /* set protocol to use in our context */
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR) return "error: 2; Problem with protocol type";

    /* apply the keylist mode to the context and set
        the keylist_mode 
        NOTE: The keylist mode flag GPGME_KEYLIST_MODE_SIGS 
            returns the signatures of UIDS with the key */
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_VALIDATE 
                                | GPGME_KEYLIST_MODE_SIGS));

    /* gpgme_op_keylist_start (gpgme_ctx_t ctx, const char *pattern, int secret_only) */
    if (domain.length() > 0){ // limit key listing to search criteria 'domain'
        err = gpgme_op_keylist_start (ctx, domain.c_str(), 0);
    } else { // list all keys
        err = gpgme_op_keylist_ext_start (ctx, NULL, secret_only, 0);
    }
    if(err != GPG_ERR_NO_ERROR) return "error: 3; Problem with keylist_start";

    std::string retVal = "{";
    while (!(err = gpgme_op_keylist_next (ctx, &key)))
     {
        /*declare nuids (Number of UIDs) 
            and nsigs (Number of signatures)
            and nsubs (Number of Subkeys)*/
        int nuids;
        int nsigs;
        int nsubs;
        int tnsigs;

        /* iterate through the keys/subkeys and add them to the std::string retVal
            - the retVal string will be parsed as JSON data in the extension */
        if (key->subkeys && key->subkeys->keyid)
            retVal += "\n\"";
            retVal += key->subkeys->keyid;
            retVal += "\":{\n\t";
        if (key->uids && key->uids->name)
            retVal += "\"name\": \"";
            std::string name_str = nonnull (key->uids->name);
            sanitize (name_str);
            retVal += name_str;
            retVal += "\",\n\t";
        if (key->subkeys && key->subkeys->fpr)
            retVal += "\"fingerprint\": \"";
            retVal += (char *) key->subkeys->fpr;
            retVal += "\",\n\t";
        if (key->uids && key->uids->email)
            retVal += "\"email\": \"";
            std::string email_str = nonnull (key->uids->email);
            sanitize (email_str);
            retVal += email_str;
            retVal += "\",\n\t";
        retVal += "\"expired\": \"";
        retVal += key->expired? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"revoked\": \"";
        retVal += key->revoked? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"disabled\": \"";
        retVal += key->disabled? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"invalid\": \"";
        retVal += key->invalid? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"secret\": \"";
        retVal += key->secret? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"protocol\": \"";
        retVal += key->protocol == GPGME_PROTOCOL_OpenPGP? "OpenPGP":
                  key->protocol == GPGME_PROTOCOL_CMS? "CMS":
                  key->protocol == GPGME_PROTOCOL_UNKNOWN? "Unknown": "[?]";
        retVal += "\",\n\t";
        retVal += "\"can_encrypt\": \"";
        retVal += key->can_encrypt? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"can_sign\": \"";
        retVal += key->can_sign? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"can_certify\": \"";
        retVal += key->can_certify? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"can_authenticate\": \"";
        retVal += key->can_authenticate? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"is_qualified\": \"";
        retVal += key->is_qualified? "1":"0";
        retVal += "\",\n\t";
        retVal += "\"subkeys\": [ ";
        for (nsubs=0, subkey=key->subkeys; subkey; subkey = subkey->next, nsubs++) {
            retVal += "{ \"subkey\": \"";
            retVal += nonnull (subkey->fpr);
            retVal += "\",\n\t\t";
            retVal += "\"expired\": \"";
            retVal += subkey->expired? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"revoked\": \"";
            retVal += subkey->revoked? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"disabled\": \"";
            retVal += subkey->disabled? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"invalid\": \"";
            retVal += subkey->invalid? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"secret\": \"";
            retVal += subkey->secret? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"can_encrypt\": \"";
            retVal += subkey->can_encrypt? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"can_sign\": \"";
            retVal += subkey->can_sign? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"can_certify\": \"";
            retVal += subkey->can_certify? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"can_authenticate\": \"";
            retVal += subkey->can_authenticate? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"is_qualified\": \"";
            retVal += subkey->is_qualified? "1":"0";     
            retVal += "\",\n\t\t";
            retVal += "\"size\": \"";
            retVal += i_to_str (subkey->length);
            retVal += "\",\n\t\t";
            retVal += "\"created\": \"";
            retVal += i_to_str(subkey->timestamp);
            retVal += "\",\n\t\t";
            retVal += "\"expires\": \"";
            retVal += i_to_str(subkey->expires);
            retVal += "\" }";
            if (subkey->next) {
                retVal += ",\n\t\t";
            }
        }
        retVal += " ],\n\t";
        retVal += "\"uids\": [ ";
        for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
            retVal += "{ \"uid\": \"";
            std::string name_str = nonnull (uid->name);
            sanitize (name_str);
            retVal += name_str;
            retVal += "\",\n\t\t";
            retVal += "\"email\": \"";
            std::string email_str = nonnull (uid->email);
            sanitize (email_str);
            retVal += email_str; 
            retVal += "\",\n\t\t";
            retVal += "\"comment\": \"";
            std::string comment_str = nonnull (uid->comment);
            sanitize (comment_str);
            retVal += comment_str;
            retVal += "\",\n\t\t";
            retVal += "\"invalid\": \"";
            retVal += uid->invalid? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"revoked\": \"";
            retVal += i_to_str(uid->revoked);
            retVal += "\",\n\t\t";
            retVal += "\"signatures_count\": \"";
            tnsigs = 0;
            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                tnsigs += 1;
            }
            retVal += i_to_str(nsigs);
            retVal += "\",\n\t\t";
            retVal += "\"signatures\": [ ";
            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                retVal += "\"";
                retVal += nonnull (sig->keyid);
                if (tnsigs > 1 && nsigs < tnsigs - 1) {
                    retVal += "\", ";
                } else {
                    retVal += "\" ";
                }
            }
            retVal += "],\n\t\t";
            retVal += "\"validity\": \"";
            retVal += uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                  uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                  uid->validity == GPGME_VALIDITY_NEVER? "never":
                  uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                  uid->validity == GPGME_VALIDITY_FULL? "full":
                  uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            retVal += "\" }";
            if (uid->next) {
                retVal += ",\n\t\t";
            }
        }
        retVal += " ]\n\t";
        gpgme_key_unref (key);
        retVal += "},";
    }
    /* the last key cannot have a trailing comma for compliant 
        JSON, so strip it off before adding the final curly-bracket */
    if (gpg_err_code (err) == GPG_ERR_EOF && retVal.length() > 2)
        retVal = retVal.substr (0, retVal.length() - 1);
    retVal += "\n}";
    if (gpg_err_code (err) != GPG_ERR_EOF) exit(6);
    err = gpgme_op_keylist_end (ctx);
    if(err != GPG_ERR_NO_ERROR) exit(7);
    result = gpgme_op_keylist_result (ctx);
    if (result->truncated)
     {
        return "error: 4; Key listing unexpectedly truncated";
     }
    gpgme_release (ctx);
    return retVal;
}

/*
    This method executes gpgauth.getKeyList with an empty string and
        secret_only=0 which returns all Public Keys in the keyring.
*/

std::string gpgAuthPluginAPI::getPublicKeyList(){
    return gpgAuthPluginAPI::getKeyList("", 0);
}

/*
    This method executes gpgauth.getKeyList with an empty string and
        secret_only=1 which returns all keys in the keyring which
        the user has the corrisponding secret key.
*/

std::string gpgAuthPluginAPI::getPrivateKeyList(){
    return gpgAuthPluginAPI::getKeyList("", 1);
}

/* 
    This method just calls gpgauth.getKeyList with a domain name
        as the parameter
*/
std::string gpgAuthPluginAPI::getDomainKey(const std::string &domain){
    return gpgAuthPluginAPI::getKeyList(domain, 0);
}

/*
    This method ensures a given UID <domain> with matching keyid
        <domain_key_fpr> has been signed by a required key
        <required_sig_keyid> and returns a GAU_trust value as the result.
        This method is intended to be called during an iteration of
        trusted key ids.
*/
    //TODO: Make these values constants and replace the usages below
    //  to use the constants
    //TODO: Add this list of constants to the documentation
    /* verifyDomainKey returns a numeric trust value -
        -7: the domain UID and/or domain key was signed by an expired key
        -6: the domain UID and/or domain key was signed by a key that
            has been revoked
        -5: the domain uid was signed by a disabled key
        -4: the  sinature has been revoked, disabled or is invalid
        -3: the uid has been revoked or is disabled or invalid.
        -2: the key belonging to the domain has been revoked or disabled, or is invalid.
        -1: the domain uid was not signed by any enabled private key and fails
             web-of-trust
        0: UID of domain_keyid was signed by an ultimately trusted private key
        1: UID of domain_keyid was signed by an expired private key that is
            ultimately trusted
        2: UID of domain_keyid was signed by a private key that is other than 
            ultimately trusted
        3: UID of domain_keyid was signed by an expired private key that is
            other than ultimately trusted
        4: domain_keyid was signed (not the UID) by an ultimately trusted
            private key
        5: domain_key was signed (not the UID) by an expired ultimately trusted
            key
        6: domain_keyid was signed (not the UID) by an other than ultimately
            trusted private key
        7: domain_key was signed (not the UID) by an expired other than
            ultimately trusted key
        8: domain_keyid was not signed, but meets web of trust
            requirements (i.e.: signed by a key that the user
            trusts and has signed, as defined by the user
            preference of "advnaced.trust_model")
    */
int gpgAuthPluginAPI::verifyDomainKey(std::string domain, 
        std::string domain_key_fpr, long uid_idx,
        std::string required_sig_keyid)
{
    int nuids;
    int nsigs;
    int domain_key_valid = -1;
    gpgme_ctx_t ctx = init();
    gpgme_key_t domain_key, user_key, secret_key, key;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
    gpgme_error_t err;
    gpgme_keylist_result_t result;
    
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx) 
                                | GPGME_KEYLIST_MODE_SIGS));

    err = gpgme_op_keylist_start (ctx, (char *) domain_key_fpr.c_str(), 0);
    if(err != GPG_ERR_NO_ERROR) return -1;

    gpgme_get_key(ctx, (char *) required_sig_keyid.c_str(), &user_key, 0);
    if (user_key) {
        while (!(err = gpgme_op_keylist_next (ctx, &domain_key))) {
            for (nuids=0, uid=domain_key->uids; uid; uid = uid->next, nuids++) {
                for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                    if (domain_key->disabled) {
                        domain_key_valid = -2;
                        break;
                    }
                    if (!strcmp(uid->name, (char *) domain.c_str()) && (uid_idx == nuids || uid_idx == -1)) {
                        if (uid->revoked)
                            domain_key_valid = -3;
                        if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())){
                            if (user_key->owner_trust == GPGME_VALIDITY_ULTIMATE)
                                domain_key_valid = 0;
                            if (user_key->owner_trust == GPGME_VALIDITY_FULL)
                                domain_key_valid = 2;
                            if (user_key->expired)
                                domain_key_valid++;
                            if (sig->invalid)
                                domain_key_valid = -4;
                            if (sig->revoked)
                                domain_key_valid = -4;
                            if (sig->expired)
                                domain_key_valid = -4;
                            if (user_key->disabled)
                                domain_key_valid = -5;
                            if (sig->status == GPG_ERR_NO_PUBKEY)
                                domain_key_valid = -1;
                            if (sig->status == GPG_ERR_GENERAL)
                                domain_key_valid = -1;
                            // the key trust is 0 (best), stop searching
                            if (domain_key_valid == 0)
                                break;
                        }
                    }
                }
            }
        }
        if (gpg_err_code (err) != GPG_ERR_EOF) exit(6);
        gpgme_get_key(ctx, (char *) domain_key_fpr.c_str(), &domain_key, 0);
        err = gpgme_op_keylist_end (ctx);

        result = gpgme_op_keylist_result (ctx);
        // the UID failed the signature test, check to see if the primary UID was signed
        // by one permissible key, or a trusted key.
        if (domain_key_valid == -1) {
            for (nuids=0, uid=domain_key->uids; uid; uid = uid->next, nuids++) {
                for (nsigs=0, sig=uid->signatures; sig; sig=sig->next, nsigs++) {
                    if (!sig->status == GPG_ERR_NO_ERROR)
                        continue;
                    // the signature keyid matches the required_sig_keyid
                    if (nuids == uid_idx && domain_key_valid == -1){
                        err = gpgme_get_key(ctx, (char *) sig->keyid, &key, 0);
                        err = gpgme_get_key(ctx, (char *) sig->keyid, &secret_key, 1);

                        if (key->owner_trust == GPGME_VALIDITY_ULTIMATE) {
                            if (!secret_key) {
                                domain_key_valid = 8;
                            } else {
                                domain_key_valid = 4;
                            }
                        }
                        if (key->owner_trust == GPGME_VALIDITY_FULL) {
                            if (!secret_key) {
                                domain_key_valid = 8;
                            } else {
                                domain_key_valid = 6;
                            }
                        }
                        if (key->expired && domain_key_valid < -1)
                            domain_key_valid += -1;
                        if (key->expired && domain_key_valid >= 0) {
                            domain_key_valid++;
                        }
                        if (sig->expired)
                            domain_key_valid = -6;
                        if (sig->invalid)
                            domain_key_valid = -2;
                        if (uid->revoked || sig->revoked)
                            domain_key_valid = -6;
                        if (sig->status == GPG_ERR_NO_PUBKEY)
                            domain_key_valid = -1;
                        if (sig->status == GPG_ERR_GENERAL)
                            domain_key_valid = -1;
                        if (key)
                            gpgme_key_unref (key);
                        if (secret_key)
                            gpgme_key_unref (secret_key);
                    }
                    if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())){
                        if (nuids == 0) {
                            if (user_key->owner_trust == GPGME_VALIDITY_ULTIMATE)
                                domain_key_valid = 4;
                            if (user_key->owner_trust == GPGME_VALIDITY_FULL)
                                domain_key_valid = 6;
                            if (user_key->expired)
                                domain_key_valid++;
                            if (sig->expired)
                                domain_key_valid = -6;
                            if (sig->invalid)
                                domain_key_valid = -2;
                            if (uid->revoked || sig->revoked)
                                domain_key_valid = -6;
                            if (sig->status == GPG_ERR_NO_PUBKEY)
                                domain_key_valid = -1;
                            if (sig->status == GPG_ERR_GENERAL)
                                domain_key_valid = -1;
                        }
                    }
                }
            }
        }
    }


    if (domain_key)
        gpgme_key_unref (domain_key);
    if (user_key)
        gpgme_key_unref (user_key);

    if (ctx)
        gpgme_release (ctx);

    return domain_key_valid;
}

std::string gpgAuthPluginAPI::gpgconf_detected() {
    gpgme_error_t err;
    std::string cfg_present;
    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    if (err != GPG_ERR_NO_ERROR) {
        cfg_present = "false";
    } else {
        cfg_present = "true";
    }

    return cfg_present;
}

std::string gpgAuthPluginAPI::get_preference(std::string preference) {
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_conf_comp_t conf, comp;
    gpgme_conf_opt_t opt;
    std::string return_value;
    json_string error;

    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    if (err) {
        return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_op_conf_load (ctx, &conf);
    if (err)
        return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    comp = conf;
    while (comp && strcmp (comp->name, "gpg"))
        comp = comp->next;

    if (comp) {
        opt = comp->options;
        while (opt && strcmp (opt->name, (char *) preference.c_str())){
#ifdef DEBUG
            printf( "opt: %s\n", opt->name);
#endif
            if (opt->next)
	            opt = opt->next;
	        else
		        opt->name = (char *) preference.c_str();
        }

        if (opt->value) {
	        //printf("from value: '%s' ", opt->value);
			//return_value = (char *) opt->value;
			return_value = "";
		} else {
			return_value = "";
		}
	}

    gpgme_conf_release (conf);

    return return_value;

}

std::string gpgAuthPluginAPI::set_preference(std::string preference, std::string pref_value) {
	gpgme_error_t err;
	json_string error;
	gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
    err = gpgme_engine_check_version (proto);
    if (err != GPG_ERR_NO_ERROR)
        return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    
    gpgme_ctx_t ctx = init();
    gpgme_conf_comp_t conf, comp;
    std::string return_code;
    
    err = gpgme_op_conf_load (ctx, &conf);
    if (err != GPG_ERR_NO_ERROR)
        return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_conf_arg_t original_arg, arg;
    gpgme_conf_opt_t opt;
    
    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, (char *) pref_value.c_str());
    
    if (err != GPG_ERR_NO_ERROR)
        return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    comp = conf;
    while (comp && strcmp (comp->name, "gpg"))
        comp = comp->next;

    if (comp) {
        opt = comp->options;
        while (opt && strcmp (opt->name, (char *) preference.c_str())){
            opt = opt->next;
        }
        
        if (opt->value) {
            original_arg = opt->value;
        } else {
            original_arg = opt->value;
            return_code = "blank";
        }
        
        /* if the new argument and original argument are the same, return 0, 
            there is nothing to do. */
        if (original_arg && !strcmp (original_arg->value.string, arg->value.string))
            return "0";

#ifdef DEBUG
        printf("setting option: %s ", opt->name);
        
        if (!strcmp(return_code.c_str(), "blank")) {
            printf("from value: '%s' ", "<empty>");
            printf("to value: '%s'\n", arg->value.string);
        } else {
            printf("from value: '%s' ", original_arg->value.string);
            printf("to value: '%s'\n", arg->value.string);
        }   
#endif
        if (opt) {
            if (!strcmp(pref_value.c_str(), "blank"))
                err = gpgme_conf_opt_change (opt, 0, NULL);
            else
                err = gpgme_conf_opt_change (opt, 0, arg);
            if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
            
            err = gpgme_op_conf_save (ctx, comp);
            if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }
    
    if (!return_code.length())
        return_code = original_arg->value.string;
        
    gpgme_conf_release (conf);

    return return_code;
}


/*
    This method passes a string to encrypt, a key to encrypt to and an
        optional key to encrypt from and calls gpgauth.gpgEncrypt.
        This method returns a string of the encrypted data.
*/
/* This method accepts 4 parameters, data, enc_to_keyid, 
    enc_from_keyid [optional], and sign [optional; default: 0:NULL:false]
    the return value is a string buffer of the result */
/* NOTE: Normally, we should call this without a value for
    encrypt_from_key to keep the anonymity of the user until after the 
    host has been validated */
std::string gpgAuthPluginAPI::gpgEncrypt(std::string data, 
        std::string enc_to_keyid, std::string enc_from_keyid,
        std::string sign)
{
    /* declare variables */
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[3] = { NULL, NULL, NULL };
    gpgme_encrypt_result_t enc_result;
    json_string error;

    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    
    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    
    err = gpgme_data_set_encoding(out, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_get_key (ctx, enc_to_keyid.c_str(),
           &key[0], 0);
    if(err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    if (enc_from_keyid.length()) {
        err = gpgme_get_key (ctx, enc_from_keyid.c_str(),
               &key[1], 0);
        if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    }

    err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err != GPG_ERR_NO_ERROR) return error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    gpgme_data_seek(in, 0, SEEK_SET);
    enc_result = gpgme_op_encrypt_result (ctx);
    if (enc_result->invalid_recipients)
    {
#ifdef DEBUG
      fprintf (stderr, "Invalid recipient encountered: %s\n",
           enc_result->invalid_recipients->fpr);
#endif
      return error.format((char *) errstr, __func__, -1, "Invalid recipient", __LINE__, __FILE__);
    }

    
    size_t out_size = 0;
    std::string out_buf;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    /* set the output object to NULL since it has
        already been released */
    out = NULL;
    
    /* if any of the gpgme objects have not yet
        been release, do so now */
    gpgme_key_unref (key[0]);
    gpgme_key_unref (key[1]);
    if (ctx)
        gpgme_release (ctx);
    if (in)
        gpgme_data_release (in);
    if (out)
        gpgme_data_release (out);

    return out_buf;
}

std::string gpgAuthPluginAPI::gpgDecrypt(std::string data)
{
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_decrypt_result_t decrypt_result;
    gpgme_verify_result_t verify_result;
    gpgme_signature_t sig;
    gpgme_data_t in, out;
    std::string out_buf, retVal;
    char *agent_info;
    int r_stat, nsigs;

    agent_info = getenv("GPG_AGENT_INFO");

    retVal = "{ ";
    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err != GPG_ERR_NO_ERROR) {
        retVal += "\"error\" : \"Problem creating gpgme input buffer\" }";
        return retVal;
    }

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR) {
        retVal += "\"error\" : \"Unable to allocate result buffer\" }";
        return retVal;
    }

    err = gpgme_op_decrypt_verify (ctx, in, out);

    decrypt_result = gpgme_op_decrypt_result (ctx);
    verify_result = gpgme_op_verify_result (ctx);

    if (err != GPG_ERR_NO_ERROR) {
        // There was an error returned while decrypting;
        //   either bad data, or signed only data
        if (verify_result->signatures) {
            if (verify_result->signatures->status != GPG_ERR_NO_ERROR) {
                retVal += "\"error\" : \"No valid GPG data to decrypt or signatures to verify; possibly bad armor.\" }";
                return retVal;
            }
        }
        if (gpg_err_code(err) == GPG_ERR_CANCELED) {
            retVal += "\"error\" : \"Passphrase cancelled\" }";
            return retVal;
        }
        if (gpg_err_code(err) == GPG_ERR_BAD_PASSPHRASE) {
            retVal += "\"error\" : \"Bad passphrase\" }";
            return retVal;
        }
        if (gpg_err_source(err) == GPG_ERR_SOURCE_PINENTRY) {
            retVal += "\"error\" : \"Pinentry failed\" }";
            return retVal;
        }
        if (gpg_err_source(err) == GPG_ERR_SOURCE_GPGAGENT) {
            retVal += "\"error\" : \"GPGAgent error\" }";
            return retVal;
        }
    }

    size_t out_size = 0;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    retVal += "\"data\" : \"" + out_buf + "\", ";
    retVal += "\"signatures\" : { ";
    /* set the output object to NULL since it has
        already been released */
    out = NULL;
    out_buf = "";

    if (verify_result->signatures) {
        for (nsigs=0, sig=verify_result->signatures; sig; sig = sig->next, nsigs++) {
            retVal += "\"";
            retVal += i_to_str(nsigs);
            retVal += "\" : { \"fingerprint\" : \"";
            retVal += (char *) sig->fpr;
            retVal += "\", \"timestamp\" : \"";
            retVal += i_to_str(sig->timestamp);
            retVal += "\", \"expiration\" : \"";
            retVal += i_to_str(sig->exp_timestamp);
            retVal += "\", \"validity\" : \"";
            retVal += sig->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                  sig->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                  sig->validity == GPGME_VALIDITY_NEVER? "never":
                  sig->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                  sig->validity == GPGME_VALIDITY_FULL? "full":
                  sig->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            retVal += "\", \"status\" : ";
            switch (gpg_err_code (sig->status))
          	{
          	case GPG_ERR_NO_ERROR:
          	  r_stat = GPGME_SIG_STAT_GOOD;
          	  retVal += "\"GOOD\"";
          	  break;

          	case GPG_ERR_BAD_SIGNATURE:
          	  r_stat = GPGME_SIG_STAT_BAD;
        	  retVal += "\"BAD\"";
          	  break;

          	case GPG_ERR_NO_PUBKEY:
          	  r_stat = GPGME_SIG_STAT_NOKEY;
          	  retVal += "\"NO_PUBKEY\"";
          	  break;

          	case GPG_ERR_NO_DATA:
          	  r_stat = GPGME_SIG_STAT_NOSIG;
          	  retVal += "\"NO_SIGNATURE\"";
          	  break;

          	case GPG_ERR_SIG_EXPIRED:
          	  r_stat = GPGME_SIG_STAT_GOOD_EXP;
          	  retVal += "\"GOOD_EXPSIG\"";
          	  break;

          	case GPG_ERR_KEY_EXPIRED:
          	  r_stat = GPGME_SIG_STAT_GOOD_EXPKEY;
          	  retVal += "\"GOOD_EXPKEY\"";
          	  break;

          	default:
          	  r_stat = GPGME_SIG_STAT_ERROR;
          	  retVal += "\"INVALID\"";
          	  break;
          	}
          	retVal += " }";
          	if (sig->next)
          	    retVal += ",";
        }
        retVal += " }";
    } else {
        retVal += "}";
    }
    retVal += " }";
    gpgme_data_release (in);
    gpgme_release (ctx);

    return retVal;
}

std::string gpgAuthPluginAPI::gpgSignUID(std::string keyid, long sign_uid,
    std::string with_keyid, long local_only, long trust_sign, 
    long trust_level)
{
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    json_string success_msg;
    std::string result = success_msg.format((char *) "{ \n\
    \"error\": \"false\",\n\
    \"result\": \"Signed UID %d of Public Key %s with Key %s\"\n }", sign_uid, keyid.c_str(), with_keyid.c_str());
    current_uid = i_to_str(sign_uid);
    json_string error;

    /* set the default key to the with_keyid 
        set_preferences returns the orginal value (if any) of
        the 'default-key' configuration parameter. We will put
        this into a variable so we can restore the setting when
        our UID Signing operation is complete (or failed)
    */
    std::string original_value = gpgAuthPluginAPI::set_preference("default-key", (char *) with_keyid.c_str());

    gpgme_release (ctx);
    ctx = init();
    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_edit (ctx, key, edit_fnc_sign, out, out);
    if (err != GPG_ERR_NO_ERROR) {
        if (err == GPGME_STATUS_ALREADY_SIGNED) {
            result = error.format((char *) errstr, __func__, err, "The selected UID has already been signed with this key.", __LINE__, __FILE__);
        } else {
            result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
        }
    }

    /* if the original value is not the new value, reset it to the previous value */
    if (strcmp ((char *) original_value.c_str(), "0")) {
        gpgAuthPluginAPI::set_preference("default-key", original_value);
    }

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);
    return result;
}

std::string gpgAuthPluginAPI::gpgEnableKey(std::string keyid)
{
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    std::string result = "{ \"error\": \"false\", \"result\": \"Key enabled\" }";
    json_string error;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    
    err = gpgme_op_edit (ctx, key, edit_fnc_enable, out, out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);
    return result;
}

std::string gpgAuthPluginAPI::gpgDisableKey(std::string keyid)
{
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    std::string result = "{ \"error\": \"false\", \"result\": \"Key disabled\" }";
    json_string error;

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_op_edit (ctx, key, edit_fnc_disable, out, out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);
    return result;

}


std::string gpgAuthPluginAPI::gpgDeleteUIDSign(std::string keyid,
    long uid, long signature) {
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    std::string result = "{ \"error\": \"false\", \"result\": \"Signature deleted\" }";
    json_string error;

    current_uid = i_to_str(uid);
    current_sig = i_to_str(signature);

    err = gpgme_op_keylist_start (ctx, keyid.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_next (ctx, &key);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    err = gpgme_op_keylist_end (ctx);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);
    
    err = gpgme_op_edit (ctx, key, edit_fnc_delsign, out, out);
    if (err != GPG_ERR_NO_ERROR)
        result = error.format((char *) errstr, __func__, gpgme_err_code (err), gpgme_strerror (err), __LINE__, __FILE__);

    current_uid = "0";
    current_sig = "0";

    gpgme_data_release (out);
    gpgme_key_unref (key);
    gpgme_release (ctx);
    return result;
}

void gpgAuthPluginAPI::progress_cb(void *self, const char *what, int type, int current, int total)
{
    if (!strcmp (what, "primegen") && !current && !total
        && (type == '.' || type == '+' || type == '!'
        || type == '^' || type == '<' || type == '>')) {
        gpgAuthPluginAPI* API = (gpgAuthPluginAPI*) self;
        API->FireEvent("onkeygenprogress", FB::variant_list_of(type));
    }
    if (!strcmp (what, "complete")) {
        gpgAuthPluginAPI* API = (gpgAuthPluginAPI*) self;
        API->FireEvent("onkeygencomplete", FB::variant_list_of("complete"));
    }
}

std::string gpgAuthPluginAPI::gpgGenKeyWorker(std::string key_type, std::string key_length, 
        std::string subkey_type, std::string subkey_length, std::string name_real, 
        std::string name_comment, std::string name_email, std::string expire_date, 
        std::string passphrase, void* APIObj,
        void(*cb_status)(
            void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    ) {

    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    std::string params = "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: " + key_type + "\n"
        "Key-Length: " + key_length + "\n"
        "Subkey-Type: " + subkey_type + "\n"
        "Subkey-Length: " + subkey_length + "\n"
        "Name-Real: " + name_real + "\n";
    if (name_comment.length() > 0) {
        params += "Name-Comment: " + name_comment + "\n";
    }
    if (name_email.length() > 0) {
        params += "Name-Email: " + name_email + "\n";
    }
    if (expire_date.length() > 0) {
        params += "Expire-Date: " + expire_date + "\n";
    } else {
        params += "Expire-Date: 0\n";
    }
    if (passphrase.length() > 0) {
        params += "Passphrase: " + passphrase + "\n";
    }
    params += "</GnupgKeyParms>\n";
    const char *parms = params.c_str();

    gpgme_genkey_result_t result;
   
    gpgme_set_progress_cb (ctx, cb_status, APIObj);

    err = gpgme_op_genkey (ctx, parms, NULL, NULL);
    if (err)
        return "Error with genkey start" + err;
    result = gpgme_op_genkey_result (ctx);

    if (!result)
    {
#ifdef DEBUG
        fprintf (stderr, "%s:%d: gpgme_op_genkey_result returns NULL\n",
           __FILE__, __LINE__);
#endif
        return "error with result";
    }
        
#ifdef DEBUG
    printf ("Generated key: %s (%s)\n", result->fpr ? result->fpr : "none",
        result->primary ? (result->sub ? "primary, sub" : "primary")
        : (result->sub ? "sub" : "none"));
#endif

    gpgme_release (ctx);
    const char* status = (char *) "complete";
    cb_status(APIObj, status, 33, 33, 33);
    return "done";
}

void gpgAuthPluginAPI::threaded_gpgGenKey(genKeyParams params)
{
    std::string result = gpgAuthPluginAPI::gpgGenKeyWorker(params.key_type, params.key_length,
        params.subkey_type, params.subkey_length, params.name_real,
        params.name_comment, params.name_email, params.expire_date,
        params.passphrase, this, &gpgAuthPluginAPI::progress_cb
    );

}

std::string gpgAuthPluginAPI::gpgGenKey(std::string key_type, 
        std::string key_length, std::string subkey_type, 
        std::string subkey_length, std::string name_real,
        std::string name_comment, std::string name_email, 
        std::string expire_date, std::string passphrase)
{

    genKeyParams params;

    params.key_type = key_type;
    params.key_length = key_length;
    params.subkey_type = subkey_type;
    params.subkey_length = subkey_length;
    params.name_real = name_real;
    params.name_comment = name_comment;
    params.name_email = name_email;
    params.expire_date = expire_date;
    params.passphrase = passphrase;
    
    boost::thread genkey_thread(
        boost::bind(
            &gpgAuthPluginAPI::threadCaller,
            this, params)
    );

    return "queued";
}

std::string gpgAuthPluginAPI::gpgImportKey(std::string ascii_key) {
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t key_buf;
    gpgme_import_result_t result;

    err = gpgme_data_new_from_mem (&key_buf, ascii_key.c_str(), ascii_key.length(), 1);

    err = gpgme_op_import (ctx, key_buf);

    result = gpgme_op_import_result (ctx);
    gpgme_data_release (key_buf);
	std::string status = "{ ";
	status += "\"considered\" : ";
	status += result->considered? "1":"0";
	status += ",\n";
	status += "\"no_user_id\" : ";
	status += result->no_user_id? "1":"0";
	status += ",\n";
	status += "\"imported\" : ";
	status += result->imported? "1":"0";
	status += ",\n";
	status += "\"imported_rsa\" : ";
	status += result->imported_rsa? "1":"0";
	status += ",\n";
	status += "\"new_user_ids\" : ";
	status += result->new_user_ids? "1":"0";
	status += ",\n";
	status += "\"new_sub_keys\" : ";
	status += result->new_sub_keys? "1":"0";
	status += ",\n";
	status += "\"new_signatures\" : ";
	status += result->new_signatures? "1":"0";
	status += ",\n";
	status += "\"new_revocations\" : ";
	status += result->new_revocations? "1":"0";
	status += ",\n";
	status += "\"secret_read\" : ";
	status += result->secret_read? "1":"0";
	status += ",\n";
	status += "\"secret_imported\" : ";
	status += result->secret_imported? "1":"0";
	status += ",\n";
	status += "\"secret_unchanged\" : ";
	status += result->secret_unchanged? "1":"0";
	status += ",\n";
	status += "\"not_imported\" : ";
	status += result->not_imported? "1":"0";
	status += ",\n";
    status += "\"imports\" : {\n\t";

    int nimports= 0;
    gpgme_import_status_t import;
    for (nimports=0, import=result->imports; import; import = import->next, nimports++) {
		status += "\"";
		status += i_to_str(nimports);
		status += "\" : { ";
		status += "\"fingerprint\" : \"";
		status += import->fpr;
		status += "\",\n\t\t";
		status += "\"result\" : \"";
		status += gpgme_strerror(import->result);
		status += "\",\n\t\t";
		status += "\"status\" : ";
		status += import->status? "1":"0";
		status += " },\n\t";
	}
    status = status.substr (0, status.length() - 3);
	status += "\n\t}\n}";
    gpgme_release (ctx);

    return status;
}

// Read-only property version
std::string gpgAuthPluginAPI::get_version()
{
    return "CURRENT_VERSION";
}
