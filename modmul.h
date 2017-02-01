#ifndef __MODMUL_H
#define __MODMUL_H

#include  <stdio.h>
#include <stdlib.h>

#include <string.h>
#include    <gmp.h>


typedef struct {
  mpz_t n;
  mpz_t e;
  mpz_t m;
} RSAEncryptionVariables;

typedef struct {
  mpz_t n;
  mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t d_p;
  mpz_t d_q;
  mpz_t i_p;
  mpz_t i_q;
  mpz_t c;
} RSADecryptionVariables;

typedef struct {
  mpz_t p;
  mpz_t q;
  mpz_t g;
  mpz_t h;
  mpz_t m;
} ElGamalEncryptionVariables;

typedef struct {
  mpz_t p;
  mpz_t q;
  mpz_t g;
  mpz_t x;
  mpz_t c1;
  mpz_t c2;
} ElGamalDecryptionVariables;


#endif
