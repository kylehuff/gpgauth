#include <locale.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>

#include <gpgme.h>

#ifndef GPGME_PROTOCOL_UNKNOWN
#define GPGME_PROTOCOL_UNKNOWN 255
#endif

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
    private:
};
