#include "gmp_ext.h"

/*
 *  TODO:
 *  - add function for precomputing T in slidingWindow
 *  - rename function slidingWindow
 *  - check base in slidingWindow
 */

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
  unsigned long t = createMask(l, i);
  printf("here %lu %i %i\n", t, i, l);
  t = t & y->_mp_d[0];
  printf("here %lu %i %i\n", t, i, l);
  while (t % 2 == 0){
    t = t / 2;
    printf("here %lu %i %i\n", t, i, l);
  }
  int r = 0;
  for (; i>=l; i--){
    if (getKthBit(y, i) == 1) {
      r = r | 0x01;
    }
    if (i != l + 1) {
      r = r << 1;
    }
  }
  return t;
}

void slidingWindow(mpz_t r, mpz_t x, mpz_t y, mpz_t mod, int k){
  unsigned long precomputedSize = pow(2ul,k)/2;
  mpz_t T[precomputedSize];

  mpz_t xSquared;
  mpz_init(xSquared);
  mpz_powm_ui(xSquared, x, 2, mod);

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
      while(getKthBit(y, l) == 0){ // TODO Possibly remove.
        l = l + 1;
      }
      u = createInt(y, i, l); // TODO rework with memcpy
    }
    unsigned int powerToAdd = 1;
    powerToAdd = powerToAdd << (i - l);
    if (powerToAdd == 1) powerToAdd = 2;
    printf("powerToAdd = %i\n", powerToAdd);
    mpz_powm_ui(r, r, powerToAdd, mod); // TODO Ask about if I can use this power here
    if (u != 0) {
      printf("U = %i\n", u);
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
