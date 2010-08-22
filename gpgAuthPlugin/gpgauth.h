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
        /* Method to verify the key associated with <domain> is
            valid and is signed by the user */
        int verifyDomainKey(string domain, string domain_key_fpr, string required_sig_keyid);
        // TODO: move to private after the removal of main()
        std::string getKeyList(string domain=NULL, int secret_only=0);
        // TODO: move to private after the removal of main()
        std::string _gpgme_version;
        std::string gpgEncrypt(string data, string enc_to_keyid, 
            string enc_from_keyid = NULL, string sign = NULL);
        std::string gpgDecrypt(string data);
    private:
};
