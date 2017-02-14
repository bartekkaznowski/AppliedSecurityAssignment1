#ifndef __GMP_EXT_H
#define __GMP_EXT_H

#include <stdlib.h>
#include <math.h>

#include    <gmp.h>

void mpz_sw_nm(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k);
void mpz_sw_m(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k, mpz_t omega, mpz_t rho);
void mpz_mont_mul(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, mpz_t omega);
void mpz_mont_omega(mpz_t r, mpz_t mod, mpz_t b);
void mpz_mont_rho_sq(mpz_t r, mpz_t mod);

#endif
