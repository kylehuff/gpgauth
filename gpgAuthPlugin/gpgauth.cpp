#include "gpgauth.h"

using namespace std;

/* 
 * Define non-class related inlines
 */

/* An inline method to convert a null char */
inline
static const char *
    nonnull (const char *s)
    {
      return s? s :"[none]";
    }

/* An inline method to convert an integer to a string */
inline
string i_to_str(const int& number)
{
   ostringstream oss;
   oss << number;
   return oss.str();
}

/* An inline method to escape single and double quotes 
    from the passed string object */
inline
void sanitize (string& str)
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

/* Class constructor */
gpgAuth::gpgAuth(){};

/* Class deconstructor */
gpgAuth::~gpgAuth(){};

/*
 * Define class methods
 */

gpgme_ctx_t gpgAuth::init(){
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    /* Initialize the locale environment.
     * The function `gpgme_check_version` must be called before any other
     * function in the library, because it initializes the thread support
     * subsystem in GPGME. (from the info page) */  
    gpgAuth::_gpgme_version = (char *) gpgme_check_version(NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    #ifdef LC_MESSAGES
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif
    err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);

    err = gpgme_new (&ctx);
    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);

    //cout << err << "\n";

    gpgAuth::is_initted = 1;

    return ctx;
};

/* TODO: Make this method private - we don't want
    web-pages able to call this method; this should
    occur from a separate method which asserts the
    data is in a gpgAuth pre/post-amble and is a sane
    string. This is not *needed* for chrome, since the
    plugin itself is private and unaccessible from
    the page, but other browsers I don't know yet */
/* This method is public, it accepts 4 parameters,
    data, enc_to_keyid, enc_from_keyid [optional], 
    and sign [optional; default: 0:NULL:false] 
    the return value is a string buffer of the result */
/* NOTE: Normally, we should call this without a value for
    encrypt_from_key to keep the anonymity of the user */
string gpgAuth::gpgEncrypt(string data, string enc_to_keyid, \
        string enc_from_keyid, string sign){
    /* declare variables */
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[3] = { NULL, NULL, NULL };
    gpgme_encrypt_result_t result;

    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err != GPG_ERR_NO_ERROR) return "error: Problem creating gpgme input buffer";

    err = gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR) return "error: Unable to set encoding on input data object";
    
    err = gpgme_data_new (&out);
    if (err != GPG_ERR_NO_ERROR) return "error: Problem creating gpgme output buffer";
    
    err = gpgme_data_set_encoding(out, GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR) return "error: Unable to set encoding on output data object";

    err = gpgme_get_key (ctx, enc_to_keyid.c_str(),
           &key[0], 0);
    if(err != GPG_ERR_NO_ERROR) return "error: unable to get key 1";

    if (enc_from_keyid.length()) {
        err = gpgme_get_key (ctx, enc_from_keyid.c_str(),
               &key[1], 0);
        if (err != GPG_ERR_NO_ERROR) return "error: unable to get key 2";
    }

    err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err != GPG_ERR_NO_ERROR) return "error: Encrypt failed.";
    gpgme_data_seek(in, 0, SEEK_SET);
    result = gpgme_op_encrypt_result (ctx);
    if (result->invalid_recipients)
    {
      fprintf (stderr, "Invalid recipient encountered: %s\n",
           result->invalid_recipients->fpr);
      if(err != GPG_ERR_NO_ERROR) return "error: Invalid recipient(s)";
    }

    
    size_t out_size = 0;
    string out_buf;
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


int gpgAuth::verifyDomainKey(string domain, string domain_key_fpr, string required_sig_keyid){
    int nuids;
    int nsigs;
    int domain_key_valid = -1;
    gpgme_ctx_t ctx = init();
    gpgme_key_t key;
    gpgme_key_t user_key;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
    gpgme_error_t err;
    gpgme_keylist_result_t result;
    
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_VALIDATE 
                                | GPGME_KEYLIST_MODE_SIGS));

    err = gpgme_op_keylist_start (ctx, (char *) domain_key_fpr.c_str(), 0);
    if(err != GPG_ERR_NO_ERROR) return -1;
    //TODO: Make these values constants and replace the usages below
    //  to use the constants
    //TODO: Add this list of constants to the documentation
    /* gpgauth.verifyDomainKey returns a numeric trust value -
        -6: the domain UID and/or domain key was signed by a key that has been
             revoked
        -5: the domain uid was signed by a disabled key
        -4: the signature is expired
        -3: the domain uid signature has been revoked
        -2: the domain uid sinature is invalid
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
    gpgme_get_key(ctx, (char *) required_sig_keyid.c_str(), &user_key, 0);
    if (user_key) {
        while (!(err = gpgme_op_keylist_next (ctx, &key)))
         {
            for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
                for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                    // the signature keyid matches the required_sig_keyid
                    if (!strcmp(uid->name, (char *) domain.c_str())) {
                        if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())){
                            cout << "signature status: " << sig->status << "\n";
                            if (user_key->owner_trust == GPGME_VALIDITY_ULTIMATE)
                                domain_key_valid = 0;
                            if (user_key->owner_trust == GPGME_VALIDITY_FULL)
                                domain_key_valid = 2;
                            if (user_key->expired)
                                domain_key_valid++;
                            if (sig->expired)
                                domain_key_valid = -4;
                            if (sig->invalid)
                                domain_key_valid = -2;
                            if (sig->revoked)
                                domain_key_valid = -7;
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
        if (key)
            gpgme_key_unref (key);
        if (gpg_err_code (err) != GPG_ERR_EOF) exit(6);
        err = gpgme_op_keylist_end (ctx);
        result = gpgme_op_keylist_result (ctx);
        if (domain_key_valid == -1) {
            err = gpgme_op_keylist_start (ctx, (char *) domain_key_fpr.c_str(), 0);
            if(err != GPG_ERR_NO_ERROR) return -1;
            while (!(err = gpgme_op_keylist_next (ctx, &key)))
             {
                uid = key->uids;
                for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                    // the signature keyid matches the required_sig_keyid
                    if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())){
                        // if the primary UID is not the same as the domain, verify
                        //  the signature
                        if (strcmp(key->uids->name, (char *) domain.c_str())) {
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
                            if (sig->revoked)
                                domain_key_valid = -7;
                            if (sig->status == GPG_ERR_NO_PUBKEY)
                                domain_key_valid = -1;
                            if (sig->status == GPG_ERR_GENERAL)
                                domain_key_valid = -1;
                        }
                    }
                }
             }
            if (gpg_err_code (err) != GPG_ERR_EOF) exit(7);
            err = gpgme_op_keylist_end (ctx);
            if(err != GPG_ERR_NO_ERROR) exit(8);
        }
    }
    result = gpgme_op_keylist_result (ctx);
    if (key)
        gpgme_key_unref (key);
    if (user_key)
        gpgme_key_unref (user_key);
    if (ctx)
        gpgme_release (ctx);
    
    return domain_key_valid;
}

/* This method is public, it returns the users keylist in a
    JSON-ish format for returning to the extension. */
string gpgAuth::getKeyList(string domain){
    /* declare variables */
    gpgme_ctx_t ctx = init();
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_keylist_result_t result;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;

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
    if (domain != ""){
        const char *pattern = domain.c_str();
        err = gpgme_op_keylist_start (ctx, pattern, 0);
    } else {
        err = gpgme_op_keylist_start (ctx, "", 0);
    }
    if(err != GPG_ERR_NO_ERROR) return "error: 3; Problem with keylist_start";

    string retVal = "{";
    while (!(err = gpgme_op_keylist_next (ctx, &key)))
     {
        /*declare nuids (Number of UIDs) 
            and nsigs (Number of signatures) */
        int nuids;
        int nsigs;

        /* iterate through the keys/subkeys and add them to the std::string retVal
            - the retVal string will be parsed as JSON data in the extension */
        if (key->subkeys && key->subkeys->keyid)
            retVal += "\n\t\"";
            retVal += key->subkeys->keyid;
            retVal += "\":{\n\t";
        if (key->uids && key->uids->name)
            retVal += "\"name\": \"";
            string name_str = nonnull (key->uids->name);
            sanitize (name_str);
            retVal += name_str;
            retVal += "\",\n\t";
        if (key->subkeys && key->subkeys->fpr)
            retVal += "\"fingerprint\": \"";
            retVal += (char *) key->subkeys->fpr;
            retVal += "\",\n\t";
        if (key->uids && key->uids->email)
            retVal += "\"email\": \"";
            string email_str = nonnull (key->uids->email);
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
        retVal += "\"uids\": [ ";
        for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
            retVal += "{ \"uid\": \"";
            string name_str = nonnull (uid->name);
            sanitize (name_str);
            retVal += name_str;
            retVal += "\",\n\t\t";
            retVal += "\"email\": \"";
            string email_str = nonnull (uid->email);
            sanitize (email_str);
            retVal += email_str; 
            retVal += "\",\n\t\t";
            retVal += "\"comment\": \"";
            string comment_str = nonnull (uid->comment);
            sanitize (comment_str);
            retVal += comment_str;
            retVal += "\",\n\t\t";
            retVal += "\"invalid\": \"";
            retVal += uid->invalid? "1":"0";
            retVal += "\",\n\t\t";
            retVal += "\"revoked\": \"";
            retVal += i_to_str(uid->revoked);
            retVal += "\",\n\t\t";
            retVal += "\"singatures\": \"";
            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                nsigs += 1;
            }
            retVal += i_to_str(nsigs);
            retVal += "\",\n\t\t";
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
    if (gpg_err_code (err) == GPG_ERR_EOF and retVal.length() > 2)
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

/* only compile main if -DDEBUG flag is set at compile time */
#ifdef DEBUG

/*
 * Define int main for testing from the command-line
 */

int main(int argc, char **argv)
{
    gpgAuth gpgauth;
    gpgme_ctx_t ctx = gpgauth.init();
    gpgme_release (ctx);
    string retval;
    //cout << "GpgME Version: " << gpgauth._gpgme_version << "\n";
    int c;
    int ca;
    int cmd = 0;
    char* enc_to_key;
    char* sign_with_key = (char *) "";
    char* data_to_enc = (char *) "";
    char* enc_from_key = (char *) "";
    char* key_to_verify = (char *) "";
    char* pattern = (char *) "";
    while ((c = getopt (argc, argv, ":l:v:d:t:f:s:")) != -1)
         switch (c) {
            //Keylist (non-option arg)
            case 'l':
                if (c == 'l') {
                    cmd = 1;
                    //cout << "optarg: " << argv[c] << "\n\n";
                    if (optarg) {
                        pattern = optarg;
                    } else {
                        pattern = (char *) "";
                    }
                }
                break;
            //Data to encrypt -d <DATA>
            case 'd':
                if (c == 'd') {
                    cmd = 2;
                }
                if (optarg[0] == '-')
                    cout << "\noptarg: " << optarg << "\n";
                data_to_enc = optarg;
                break;
            //Encrypt from key -f <KEY UID or ID>
            case 'f':
                enc_from_key = optarg;
                break;
            //Encrypt to key -f <KEY UID or ID>
            case 't':
                enc_to_key = optarg;
                break;
            //Sign -s <KEY UID or ID>
            case 's':
                sign_with_key = optarg;
                break;
            //Verifify -v <KEY UID or ID>
            case 'v':
                if (c == 'v') {
                    cmd = 3;
                    key_to_verify = optarg;
                }
                break;
            case ':':
                if (argv[optind - 1][1] == 'l') {
                    cmd = 1;
                } else {
                    fprintf(stderr, "Option -%c requires an operand\n", optopt);
                }
                break;
            default:
                for (ca = optind; ca < argc; ca++)
                    printf ("Non-option argument %s\n", argv[ca]);
                fprintf(stderr, "Usage: -d <DATA_TO_ENC> -t <ENC_TO_KEY> [-f <ENC_FROM_KEY> -s]\n");
                return 0;
    }
    if (cmd == 1) {
        retval = gpgauth.getKeyList(pattern);
    } else if (cmd == 2) {
        cout << "data to encrypt: " << data_to_enc << "\nencrypt to: " << enc_to_key << "\nencrypt from: " << enc_from_key << "\nsign with: " << sign_with_key << "\n";
        retval = gpgauth.gpgEncrypt(data_to_enc, enc_to_key, enc_from_key, sign_with_key);
    } else if (cmd == 3) {
        string domain_key_fpr = "934DA17C3944B426";
        string domain = "www.gpgauth.org";
        retval = "Checking key " + domain_key_fpr + "\n";
        string required_sig_keyid = "0DF9C95C3BE1A023";
        //gpgme_ctx_t ctx = gpgauth.init();
        int key_valid = gpgauth.verifyDomainKey(domain, domain_key_fpr, required_sig_keyid);
        if (key_valid >= 0) {
            retval += "key passes validity test with a trust level of " + i_to_str(key_valid);
        } else {
            retval += "key failed validty test with a trust level of " + i_to_str(key_valid);
        }
    }
    cout << retval << "\n";
    return 0;
};

#endif
