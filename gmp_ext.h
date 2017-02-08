#ifndef __GMP_EXT_H
#define __GMP_EXT_H

#include <stdlib.h>
#include <math.h>

#include    <gmp.h>

void slidingWindow(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k);
void mpz_mont_mul(mpz_t r, mpz_t x, mpz_t y, mpz_t mod);

#endif
