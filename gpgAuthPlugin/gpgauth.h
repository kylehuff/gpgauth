#include <locale.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>

#include <gpgme.h>

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
