#include <stdint.h>

const char *blind_ios(const char *to);

void destroy_ios();

const char *generate_check_parameter_ios();

void new_ios(const char *signer_pubkey, const char *judge_pubkeys, unsigned int id);

void set_subset_ios(const char *to);

const char *unblind_ios(const char *to);
