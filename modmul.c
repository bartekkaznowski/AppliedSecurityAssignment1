#include "modmul.h"


void rsaEncrypt(RSAEncryptionVariables ev){
  mpz_t c;
  mpz_init(c);

  // using mpz_powm_sec instead of mpz_powm for security reasons (side-channel attack)
  mpz_powm_sec(c, ev.m, ev.e, ev.n);

  gmp_printf ("%ZX\n", c);
  mpz_clear(c);
}

/*
Perform stage 1:

- read each 3-tuple of N, e and m from stdin,
- compute the RSA encryption c, then
- write the ciphertext c to stdout.
*/
void stage1() {
  RSAEncryptionVariables ev;

  mpz_init(ev.n);
  mpz_init(ev.e);
  mpz_init(ev.m);

  for (int i = 0; i < 10; i++){
    if(1 != gmp_scanf("%ZX", ev.n)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.e)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.m)){
      abort();
    }
    rsaEncrypt(ev);
  }
  
  mpz_clear(ev.n);
  mpz_clear(ev.e);
  mpz_clear(ev.m);
}

void rsaDecrypt(RSADecryptionVariables dv){
  mpz_t m;
  mpz_init(m);

  // using mpz_powm_sec instead of mpz_powm for security reasons (side-channel attack)
  mpz_powm_sec(m, dv.c, dv.d, dv.n);

  gmp_printf ("%ZX\n", m);
  mpz_clear(m);
}

/*
Perform stage 2:

- read each 9-tuple of N, d, p, q, d_p, d_q, i_p, i_q and c from stdin,
- compute the RSA decryption m, then
- write the plaintext m to stdout.
*/

void stage2() {
  RSADecryptionVariables dv;
  mpz_init(dv.n);
  mpz_init(dv.d);
  mpz_init(dv.p);
  mpz_init(dv.q);
  mpz_init(dv.d_p);
  mpz_init(dv.d_q);
  mpz_init(dv.i_p);
  mpz_init(dv.i_q);
  mpz_init(dv.c);

  for (int i = 0; i < 10; i++){
    if(1 != gmp_scanf("%ZX", dv.n)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.d)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.p)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.q)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.d_p)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.d_q)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.i_p)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.i_q)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", dv.c)){
      abort();
    }
    rsaDecrypt(dv);
  }
  
  mpz_clear(dv.n);
  mpz_clear(dv.d);
  mpz_clear(dv.p);
  mpz_clear(dv.q);
  mpz_clear(dv.d_p);
  mpz_clear(dv.d_q);
  mpz_clear(dv.i_p);
  mpz_clear(dv.i_q);
  mpz_clear(dv.c);
}

// TODO change "randomness"
void elGamalEncrypt(ElGamalEncryptionVariables ev){
  mpz_t c1;
  mpz_t c2;
  mpz_t r;
  
  mpz_init(c1);
  mpz_init(c2);
  mpz_init(r);
  
  unsigned long int seed = 123456;

  gmp_randstate_t r_state;

  gmp_randinit_default (r_state);
  gmp_randseed_ui(r_state, seed);

  mpz_urandomm(r,r_state, ev.q);

  mpz_pow_ui (c1, ev.g, 1ul);

  mpz_pow_ui (c2, ev.h, 1ul);
  mpz_mul(c2, c2, ev.m);

  gmp_printf ("%ZX\n", c1);
  gmp_printf ("%ZX\n", c2);

  gmp_randclear(r_state);
  mpz_clear(r);
  mpz_clear(c1);
  mpz_clear(c2);
}

/*
Perform stage 3:

- read each 5-tuple of p, q, g, h and m from stdin,
- compute the ElGamal encryption c = (c_1,c_2), then
- write the ciphertext c to stdout.
*/

void stage3() {
  ElGamalEncryptionVariables ev;
  
  mpz_init(ev.p);
  mpz_init(ev.q);
  mpz_init(ev.g);
  mpz_init(ev.h);
  mpz_init(ev.m);

  for (int i = 0; i < 10; i++){
    if(1 != gmp_scanf("%ZX", ev.p)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.q)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.g)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.h)){
      abort();
    }
    if(1 != gmp_scanf("%ZX", ev.m)){
      abort();
    }
    elGamalEncrypt(ev);
  }

  mpz_clear(ev.p);
  mpz_clear(ev.q);
  mpz_clear(ev.g);
  mpz_clear(ev.h);
  mpz_clear(ev.m);
}

/*
Perform stage 4:

- read each 5-tuple of p, q, g, x and c = (c_1,c_2) from stdin,
- compute the ElGamal decryption m, then
- write the plaintext m to stdout.
*/

void stage4() {

  // fill in this function with solution

}

/*
The main function acts as a driver for the assignment by simply invoking
the correct function for the requested stage.
*/

int main( int argc, char* argv[] ) {
  if( 2 != argc ) {
    abort();
  }

  if     ( !strcmp( argv[ 1 ], "stage1" ) ) {
    stage1();
  }
  else if( !strcmp( argv[ 1 ], "stage2" ) ) {
    stage2();
  }
  else if( !strcmp( argv[ 1 ], "stage3" ) ) {
    stage3();
  }
  else if( !strcmp( argv[ 1 ], "stage4" ) ) {
    stage4();
  }
  else {
    abort();
  }

  return 0;
}
