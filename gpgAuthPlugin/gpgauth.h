#define _FILE_OFFSET_BITS 64
#include <locale.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>

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
        void init();
        int is_initted;
        // TODO: move to private after the removal of main()
        std::string getKeyList();
        // TODO: move to private after the removal of main()
        std::string _gpgme_version;
        std::string gpgEncrypt(string text, string enc_to_keyid, 
            string enc_from_keyid = "", int sign = 0);
    private:
};
