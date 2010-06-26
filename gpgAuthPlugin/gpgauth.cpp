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


/* Class constructor */
gpgAuth::gpgAuth(){};

/* Class deconstructor */
gpgAuth::~gpgAuth(){};

/*
 * Define class methods
 */

void gpgAuth::init(){
    gpgme_error_t err;
    char *_gpgme_version;
    /* Initialize the locale environment.
     * The function `gpgme_check_version' must be called before any other
     * function in the library, because it initializes the thread support
     * subsystem in GPGME. (from the info page) */
    gpgAuth::_gpgme_version = (char *) gpgme_check_version(NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    #ifdef LC_MESSAGES
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif
    err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    gpgAuth::is_initted = 1;
};

/* This method is public, it returns the users keylist in a
    JSON-ish format for returning to the extension. */
//TODO: make this method private and expose 2 other methods to use the \
        logic of this method to get the keylist, one which returns all \
        and one which accepts arguments to filter for a specific key-id
string gpgAuth::getKeyList(){
    /* declare variables */
    gpgme_ctx_t ctx;
    gpgme_key_t key;
    gpgme_data_t data;
    gpgme_engine_info_t enginfo;
    gpgme_keylist_result_t result;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;

    /* initiate a new instance (context) of gpgme and
        assign it to ctx, catch any gpgme_error */
    gpgme_error_t err = gpgme_new (&ctx);
    if(err != GPG_ERR_NO_ERROR) return "error: 1; Unable to init new gpgme context";

    /* set protocol to use in our context */
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR) return "error: 2; Problem with protocol type";

    /* apply the keylist mode to the context and set
        the keylist_mode 
        NOTE: The keylist mode flag GPGME_KEYLIST_MODE_SIGS 
            returns the signatures of UIDS with the key */
        //TODO: Parse and validate the signatures on UIDS \
            for methods other than a generic key-listing \
            for the purpose of populating the GUI key-list
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_VALIDATE 
                                | GPGME_KEYLIST_MODE_SIGS));

    err = gpgme_op_keylist_start (ctx, NULL, 0);
    if(err != GPG_ERR_NO_ERROR) return "error: 3; Problem with keylist_start";

    string retVal = "{\n";
    while (!(err = gpgme_op_keylist_next (ctx, &key)))
     {
        /*declare nuids (Number of UIDs) 
            and nsigs (Number of signatures) */
        int nuids;
        int nsigs;

        /* iterate through the subkeys and add them to the string 
            the string will be parsed as JSON data in the extension */
        for (nuids=0, uid=key->uids; uid; uid = uid->next)
            nuids++;
        if (key->subkeys && key->subkeys->keyid)
            retVal += "\t'";
            retVal += key->subkeys->keyid;
            retVal += "': {\n\t\t";
        if (key->subkeys && key->subkeys->fpr)
            retVal += "'fingerprint': '";
            retVal += (char *) key->subkeys->fpr;
            retVal += "',\n\t\t";
        if (key->uids && key->uids->name)
            retVal += "'name': '";
            retVal += (char *) key->uids->name;
            retVal += "',\n\t\t";
        if (key->uids && key->uids->email)
            retVal += "'email': '";
            retVal += (char *) key->uids->email;
            retVal += "',\n\t\t";
        retVal += "'expired': '";
        retVal += key->expired? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'revoked': '";
        retVal += key->revoked? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'disabled': '";
        retVal += key->disabled? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'invalid': '";
        retVal += key->invalid? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'secret': '";
        retVal += key->secret? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'protocol': '";
        retVal += key->protocol == GPGME_PROTOCOL_OpenPGP? "OpenPGP":
                  key->protocol == GPGME_PROTOCOL_CMS? "CMS":
                  key->protocol == GPGME_PROTOCOL_UNKNOWN? "Unknown": "[?]";
        retVal += "',\n\t\t";
        retVal += "'can_encrypt': '";
        retVal += key->can_encrypt? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'can_sign': '";
        retVal += key->can_sign? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'can_certify': '";
        retVal += key->can_certify? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'can_authenticate': '";
        retVal += key->can_authenticate? "1":"0";
        retVal += "',\n\t\t";
        retVal += "'is_qualified': '";
        retVal += key->is_qualified? "1":"0";
        retVal += "',\n\t\t";
        if (nuids > 0)
            retVal += "'uids': {\n";
        for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
            retVal += "\t\t\t'";
            retVal += nonnull(uid->name);
            retVal += "': {\n\t\t\t\t";
            retVal += "'email': '";
            retVal += nonnull(uid->email);
            retVal += "',\n\t\t\t\t";
            retVal += "'comment': '";
            retVal += nonnull(uid->comment);
            retVal += "',\n\t\t\t\t";
            retVal += "'invalid': '";
            retVal += uid->invalid? "1":"0";
            retVal += "',\n\t\t\t\t";
            retVal += "'revoked': '";
            retVal += i_to_str(uid->revoked);
            retVal += "',\n\t\t\t\t";
            retVal += "'singatures': '";
            for (nsigs=0, sig=uid->signatures; sig; sig = sig->next, nsigs++) {
                nsigs += 1;
            }
            retVal += i_to_str(nsigs);
            
            retVal += "',\n\t\t\t\t";
            retVal += "'validity': '";
            retVal += uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                  uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                  uid->validity == GPGME_VALIDITY_NEVER? "never":
                  uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                  uid->validity == GPGME_VALIDITY_FULL? "full":
                  uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";            
            retVal += "'\n\t\t\t},\n";
        }
        retVal += "\t\t}\n";
        gpgme_key_unref (key);
        retVal += "\t},\n";
     }
     retVal += "};";
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
 * Define int main for testing from the command-line
 */

int main(int argc, char **argv)
{
    if (argc)
    { argc--; argv++; }

    if (argc > 1)
    {
      fputs ("usage: gpgauth [USERID]\n", stderr);
      exit (1);
    }
    gpgAuth gpgauth;    
    gpgauth.init();
    cout << "GpgME Version: " << gpgauth._gpgme_version << "\n";
    string retval = gpgauth.getKeyList();
    cout << retval << "\n";
    return 0;
};
