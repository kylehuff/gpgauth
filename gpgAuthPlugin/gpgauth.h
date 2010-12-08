#define _FILE_OFFSET_BITS 64
#include <locale.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>
#include <string.h>

#include <gpgme.h>

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifndef GPGME_PROTOCOL_UNKNOWN
#define GPGME_PROTOCOL_UNKNOWN 255
#endif

using namespace std;

class gpgAuth {
    public:
        gpgAuth(void);
        ~gpgAuth(void);
        gpgme_ctx_t init();
        int is_initted;
        std::string set_preference(string preference, string pref_value);
        /* Method to verify the key associated with <domain> is
            valid and is signed by the user */
        int verifyDomainKey(string domain, string domain_key_fpr, 
            int uid_idx, string required_sig_keyid);
        std::string getKeyList(string domain=NULL, int secret_only=0);
        std::string _gpgme_version;
        std::string gpgEncrypt(string data, string enc_to_keyid, 
            string enc_from_keyid=NULL, string sign=NULL);
        std::string gpgDecrypt(string data);
        std::string gpgSignUID(string keyid, int sign_uid, string with_keyid, 
            bool local_only=1, bool trust_sign=1, string trust_sign_level="M");
        std::string gpgDeleteUIDSign(string keyid, int uid, int signature);
        std::string gpgGenKey(string key_type, string key_length, 
            string subkey_type, string subkey_length, string name_real,
            string name_comment, string name_email, string expire_date,
            string passphrase, void* APIObj, void(*cb_status)(void *self,
                                                const char *what,
                                                int type,
                                                int current,
                                                int total
                                            )
        );
        std::string gpgImportKey(string ascii_key);
    private:
};
