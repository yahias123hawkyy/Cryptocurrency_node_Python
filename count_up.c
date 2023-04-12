#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

#define TARGET_NONCE_STR "0000000000000000000000000000000000000000000000000000002634878840"

int main(void)
{
	int ret = 0;

	mpz_t nonce;
	mpz_t target_nonce;

	mpz_init_set_ui(nonce, 0);
	if (mpz_init_set_str(target_nonce, TARGET_NONCE_STR, 16) < 0) {
		ret = -1;
		goto out;
	}

	while (mpz_cmp(nonce, target_nonce) < 0) {
		mpz_t subtarget;
		mpz_init_set(subtarget, nonce);
		mpz_add_ui(subtarget, subtarget, 1024*1024);

		while (mpz_cmp(nonce, subtarget) < 0) {
			mpz_add_ui(nonce, nonce, 1);
		}

		char *nonce_str = mpz_get_str(NULL, 16, nonce);
		if (nonce_str == NULL) {
			goto out;
		}
		printf("0x%64s\n", nonce_str);
		free(nonce_str);

		mpz_clear(subtarget);
	}

	char *nonce_str = mpz_get_str(NULL, 16, nonce);
	if (nonce_str == NULL) {
		goto out;
	}
	printf("0x%64s\n", nonce_str);
	free(nonce_str);

out:
	mpz_clear(nonce);
	mpz_clear(target_nonce);

	return ret;
}
