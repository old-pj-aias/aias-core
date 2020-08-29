void new(const char *signer_privkey, const char *signer_pubkey);
void destroy();

void set_blinded_digest(const char *blinded_digest);
char *setup_subset();

int check(const char *check_parameter);

char *sign();
