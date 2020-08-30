#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

extern "C" {

char *blind_ios(const char *to);

void destroy_ios();

char *generate_check_parameter_ios();

void new_ios(const char *signer_pubkey, const char *judge_pubkeys);

void set_subset_ios(const char *to);

char *unblind_ios(const char *to);

} // extern "C"
