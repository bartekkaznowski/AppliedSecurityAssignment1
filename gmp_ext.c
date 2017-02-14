#include "gmp_ext.h"

unsigned char getKthBit(mpz_t n, unsigned long k){
  if (n->_mp_size == 0) {
    return 0;
  };
  unsigned long pos = k/(sizeof(mp_limb_t) * 8);

  return ((n->_mp_d[pos] >> (k % (sizeof(mp_limb_t) * 8))) & 0x01);
}

unsigned createMask(unsigned a, unsigned b)
{
   unsigned r = 0;
   for (unsigned i=a; i<=b; i++)
       r |= 1 << i;

   return r;
}

int createInt(mpz_t y, int i, int l){
  int r = 0;
  for (; i>=l; i--){
    if (getKthBit(y, i) == 1) {
      r = r | 0x01;
    }
    if ((i != l)) {
      r = r << 1;
    }
  }
  return r;
}

void mpz_sw_nm(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k){
  unsigned long precomputedSize = (1ul << k)/2;
  mpz_t T[precomputedSize];

  mpz_t xSquared;
  mpz_init(xSquared);
  mpz_mul(xSquared, x, x);
  mpz_mod(xSquared, xSquared, mod);

  mpz_init(T[0]);
  mpz_set(T[0], x);
  for (int i = 1; i < precomputedSize; i++){
    mpz_init(T[i]);
    mpz_mul(T[i], T[i-1], xSquared);
    mpz_mod(T[i], T[i], mod);
  }

  mpz_set_ui(r, 1ul);

  int l = 0;
  int u = 0;
  int i = abs(y->_mp_size) * sizeof(mp_limb_t) * 8;
  while(i >= 0){
    if (getKthBit(y, i) == 0){
      l = i;
      u = 0;
    } else {
      l = i - k + 1;
      l = (l > 0)?(l):(0);
      while(getKthBit(y, l) == 0){
        l = l + 1;
      }
      u = createInt(y, i, l);
    }
    unsigned int powerToAdd = 1;
    powerToAdd = powerToAdd << (i - l + 1);
    mpz_powm_ui(r, r, powerToAdd, mod);
    if (u != 0) {
      mpz_mul(r, r, T[(int)floor(((u-1)/2))]);
      mpz_mod(r, r, mod);
    }
    i = l - 1;
  }
  for (int i = 0; i < precomputedSize; i++){
    mpz_clear(T[i]);
  }
  mpz_clear(xSquared);
}

void mpz_sw_m(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k, mpz_t omega, mpz_t rho){
  unsigned long precomputedSize = (1ul << k)/2;
  mpz_t T[precomputedSize];

  mpz_t xSquared, temp, one;
  mpz_init(xSquared);
  mpz_init(temp);
  mpz_init(one);
  mpz_set_ui(one, 1ul);

  mpz_mont_mul (xSquared, x, x, mod, omega);

  mpz_init(T[0]);
  mpz_set(T[0], x);
  for (int i = 1; i < precomputedSize; i++){
    mpz_init(T[i]);
    mpz_mont_mul (T[i], T[i-1], xSquared, mod, omega);
  }

  mpz_mont_mul(r, one, rho, mod, omega);

  int l = 0;
  int u = 0;
  int i = abs(y->_mp_size) * sizeof(mp_limb_t) * 8 - 1;
  while(i >= 0){
    if (getKthBit(y, i) == 0){
      l = i;
      u = 0;
    } else {
      l = i - k + 1;
      l = (l > 0)?(l):(0);
      while(getKthBit(y, l) == 0){
        l = l + 1;
      }
      u = createInt(y, i, l); // TODO rework with memcpy
    }
    for ( int n = 0; n < i-l+1; ++n ) {
      mpz_mont_mul(temp, r, r, mod, omega);
      mpz_set(r, temp);
    }

    if ( u != 0 ) {
      mpz_mont_mul(temp, r, T[(u-1)/2], mod, omega);
      mpz_set(r, temp);
    }
    i = l - 1;
  }
  for (int i = 0; i < precomputedSize; i++){
    mpz_clear(T[i]);
  }
  mpz_clear(xSquared);
  mpz_clear(temp);
  mpz_clear(one);
}

void mpz_mont_omega(mpz_t r, mpz_t mod, mpz_t b){
  mpz_set_ui(r, 1);
  for (int i = 1; i <= mp_bits_per_limb-1; i++){
    mpz_mul(r, r, r);
    mpz_mod(r, r, b);
    mpz_mul(r, r, mod);
    mpz_mod(r, r, b);
  }
  mpz_neg(r, r);
  mpz_mod(r, r, b);
}

void mpz_mont_rho_sq(mpz_t r, mpz_t mod){
  mpz_set_ui(r, 1);
  for (long int i = 1; i <= 2 * mpz_size(r) * mp_bits_per_limb; i++){
    mpz_add(r, r, r);
    mpz_mod(r, r, mod);
  }
}

void mpz_mont_mul(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, mpz_t omega){
  mpz_set_ui(r, 0ul);

  mpz_t u, b, temp1, temp2;

  mpz_init(u);
  mpz_init(b);
  mpz_init(temp1);
  mpz_init(temp2);

  mpz_set_ui(b, 1ul);
  mpz_mul_2exp (b, b, mp_bits_per_limb);

  for (int i = 0; i <= mpz_size(mod) - 1; i++){
    if (i < y->_mp_size) {
      mpz_set_ui(u, y->_mp_d[i]);
    } else {
      mpz_set_ui(u, 0ul);
    }
    if (x->_mp_size == 0) {
      mpz_mul_ui(u, u, 0ul);
    } else {
      mpz_mul_ui(u, u, x->_mp_d[0]);
    }
    if (r->_mp_size != 0) {
      mpz_add_ui(u, u, r->_mp_d[0]);
    } else {
      mpz_add_ui(u, u, 0ul);
    }

    mpz_mul(u, u, omega);
    mpz_mod(u, u, b);

    if (i < y->_mp_size) {
      mpz_set_ui(temp1, y->_mp_d[i]);
    } else {
      mpz_set_ui(temp1, 0ul);
    }

    mpz_mul(temp1, temp1, x);
    mpz_set(temp2, u);
    mpz_mul(temp2, temp2, mod);
    mpz_add(r, r, temp1);
    mpz_add(r, r, temp2);
    mpz_tdiv_q_2exp(r, r, mp_bits_per_limb);
  }
  if (mpz_cmp(r, mod) >= 0) {
    mpz_sub(r, r, mod);
  }
  mpz_clear(u);
  mpz_clear(b);
  mpz_clear(temp1);
  mpz_clear(temp2);
}
