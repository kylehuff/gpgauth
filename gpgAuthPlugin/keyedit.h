#include <stdlib.h>
#include <iostream>

/* Global variables for the handling of UID signing or
    deleting signatures on UIDs */
// index number of the UID which contains the signature to delete/revoke
std::string current_uid;
// index number for the signature to select
std::string current_sig;
// Used as iter count for current signature index
static int signature_iter = 1;
static int progress_called;

static void
progress (void *self, const char *what, int type, int current, int total)
{
  if (!strcmp (what, "primegen") && !current && !total
        && (type == '.' || type == '+' || type == '!'
        || type == '^' || type == '<' || type == '>'))
    {
      printf ("%c", type);
      fflush (stdout);
      progress_called = 1;
    }
  else
    {
      fprintf (stderr, "unknown progress `%s' %d %d %d\n", what, type,
        current, total);
      exit (1);
    }
}

gpgme_error_t
edit_fnc_sign (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
    /* this is for signing */
    char *response = NULL;

    fprintf (stdout, "[-- Code: %i, %s --]\n", status, args);

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    response = (char *) "fpr";
                    break;

                case 1:
                    response = (char *) current_uid.c_str();
                    break;

                case 2:
                    response = (char *) "tlsign";
                    break;

                default:
                    step = 0;
                    response = (char *) "quit";
                    break;
            }
            step++;
        }
        else if (!strcmp (args, "keyedit.save.okay"))
            response = (char *) "Y";
        else if (!strcmp (args, "trustsig_prompt.trust_value"))
            response = (char *) "1";
        else if (!strcmp (args, "trustsig_prompt.trust_depth"))
            response = (char *) "1";
        else if (!strcmp (args, "trustsig_prompt.trust_regexp"))
            response = (char *) "";
        else if (!strcmp (args, "sign_uid.okay"))
            response = (char *) "y";
        else if (!strcmp (args, "passphrase.enter"))
            response = (char *) "";
    }

    if (response) {
        write (fd, response, strlen (response));
        write (fd, "\n", 1);
    }
    args = "";
    return 0;
}


gpgme_error_t
edit_fnc_delsign (void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
  /* this works for deleting signatures -
    you must populate the global variables before calling this method for this to work -
        current_uid = <the index of the UID which has the signature you wish to delete>
        current_sig = <the index of signature you wish to delete>  */
    char *response = NULL;

    fprintf (stdout, "[-- Code: %i, %s --]\n", status, args);

    if (fd >= 0) {
        if (!strcmp (args, "keyedit.prompt")) {
            static int step = 0;
        
            switch (step) {
                case 0:
                    response = (char *) "fpr";
                    break;

                case 1:
                    signature_iter = 1;
                    response = (char *) current_uid.c_str();
                    break;

                case 2:
                    response = (char * ) "delsig";
                    break;
                    
                default:
                    step = 0;
                    response = (char *) "quit";
                    break;
            }
            step++;
        } else if (!strcmp (args, "keyedit.save.okay")) {
            response = (char *) "Y";
        } else if (!strcmp (args, "keyedit.delsig.valid") || 
            !strcmp (args, "keyedit.delsig.invalid") ||
            !strcmp (args, "keyedit.delsig.unknown") ||
            !strcmp (args, "keyedit.delsig.selfsig") ) {
            if (signature_iter == atoi(current_sig.c_str())) {
                response = (char *) "y";
                current_sig = "0";
                current_uid = "0";
                signature_iter = 0;
            } else {
                response = (char *) "n";
            }
            signature_iter++;
        } else if (!strcmp (args, "passphrase.enter")) {
            response = (char *) "";
        }
    }

    if (response) {
        write (fd, response, strlen (response));
        write (fd, "\n", 1);
    }
    return 0;
}

//int
//main (int argc, char **argv)
//{
//  gpgme_ctx_t ctx;
//  gpgme_error_t err;
//  gpgme_data_t out = NULL;
//  gpgme_key_t key = NULL;
//  const char *pattern = "ipatrol";
//  char *agent_info;

//  init_gpgme (GPGME_PROTOCOL_OpenPGP);

//  int x = set_pref();
//  if (x)
//    printf("error was: %i\n", x);

//  err = gpgme_new (&ctx);
//  fail_if_err (err);
//  err = gpgme_data_new (&out);
//  fail_if_err (err);

//  agent_info = getenv("GPG_AGENT_INFO");
//  if (!(agent_info && strchr (agent_info, ':')))
//    gpgme_set_passphrase_cb (ctx, passphrase_cb, 0);

//  err = gpgme_op_keylist_start (ctx, pattern, 0);
//  fail_if_err (err);
//  err = gpgme_op_keylist_next (ctx, &key);
//  fail_if_err (err);
//  err = gpgme_op_keylist_end (ctx);
//  fail_if_err (err);

//  current_delsig_uid = "1";
//  current_delsig_idx = "3";

//  err = gpgme_op_edit (ctx, key, edit_fnc_sign, out, out);
//  fail_if_err (err);

//  fputs ("[-- Last response --]\n", stdout);
//  
//  gpgme_data_release (out);
//  gpgme_key_unref (key);
//  gpgme_release (ctx);

//  return 0;
//}
