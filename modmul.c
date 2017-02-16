#include "modmul.h"
#include "gmp_ext.h"
#include <openssl/rand.h>
#include "rdrand.h"

int getSeed(unsigned int bytes, unsigned char * randomBinStr) {
  return rdrand_get_bytes(bytes, randomBinStr);
}

void rsaEncrypt(RSAEncryptionVariables ev) {
  mpz_t c;
  mpz_init(c);

  mpz_t omega, rho, b, m_m, c_m, one;
  mpz_init(omega);
  mpz_init(rho);
  mpz_init(b);
  mpz_init(m_m);
  mpz_init(c_m);
  mpz_init(one);

  mpz_set_ui(one, 1ul);
  mpz_set_ui(b, 1ul);
  mpz_mul_2exp(b, b, mp_bits_per_limb);

  mpz_mont_omega(omega, ev.n, b);
  mpz_mont_rho_sq(rho, ev.n);
  mpz_mont_mul(m_m, ev.m, rho, ev.n, omega);

  mpz_sw_m(c_m, m_m, ev.e, ev.n, 4, omega, rho);

  mpz_mont_mul(c, c_m, one, ev.n, omega);

  gmp_printf("%ZX\n", c);
  mpz_clear(c);
  mpz_clear(c_m);
  mpz_clear(m_m);
  mpz_clear(omega);
  mpz_clear(one);
  mpz_clear(rho);
  mpz_clear(b);
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

  char buffer[1024];
  size_t contentSize = 1;
  char * content = malloc(sizeof(char) * 1024);
  if (content == NULL) {
    fprintf(stderr, "Failed to allocated memory.\n");
    exit(1);
  }
  content[0] = '\0';
  while (fgets(buffer, 1024, stdin)) {
    contentSize += strlen(buffer);
    content = realloc(content, contentSize);
    if (content == NULL) {
      fprintf(stderr, "Failed to allocated memory.\n");
      free(content);
      exit(1);
    }
    strcat(content, buffer);
  }

  if (ferror(stdin)) {
    free(content);
    fprintf(stderr, "Error reading stdin.\n");
    exit(1);
  }

  char * num;
  num = strtok(content, "\n");
  while (num != NULL) {
    mpz_set_str(ev.n, num, 16);

    num = strtok(NULL, "\n");
    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.e, num, 16);

    num = strtok(NULL, "\n");
    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.m, num, 16);

    num = strtok(NULL, "\n");
    rsaEncrypt(ev);

  }

  mpz_clear(ev.n);
  mpz_clear(ev.e);
  mpz_clear(ev.m);
}

void rsaDecrypt(RSADecryptionVariables dv) {
  mpz_t m;
  mpz_t m1;
  mpz_t m2;
  mpz_t h;
  mpz_init(m);
  mpz_init(m1);
  mpz_init(m2);
  mpz_init(h);

  mpz_sw_nm(m1, dv.c, dv.d_p, dv.p, 4);
  mpz_sw_nm(m2, dv.c, dv.d_q, dv.q, 4);
  if (mpz_cmp(m1, m2) >= 0) {
    mpz_sub(m, m1, m2);
    mpz_mul(m, m, dv.i_q);
    mpz_mod(m, m, dv.p);
    mpz_mul(m, m, dv.q);
    mpz_add(m, m, m2);
  } else {
    mpz_sub(m, m2, m1);
    mpz_mul(m, m, dv.i_p);
    mpz_mod(m, m, dv.q);
    mpz_mul(m, m, dv.p);
    mpz_add(m, m, m1);
  }
  gmp_printf("%ZX\n", m);
  mpz_clear(m);
  mpz_clear(m1);
  mpz_clear(m2);
  mpz_clear(h);
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

  char buffer[1024];
  size_t contentSize = 1;
  char * content = malloc(sizeof(char) * 1024);
  if (content == NULL) {
    fprintf(stderr, "Failed to allocated memory.\n");
    exit(1);
  }
  content[0] = '\0';
  while (fgets(buffer, 1024, stdin)) {
    contentSize += strlen(buffer);
    content = realloc(content, contentSize);
    if (content == NULL) {
      fprintf(stderr, "Failed to allocated memory.\n");
      free(content);
      exit(1);
    }
    strcat(content, buffer);
  }

  if (ferror(stdin)) {
    free(content);
    fprintf(stderr, "Error reading stdin.\n");
    exit(1);
  }

  char * num;
  num = strtok(content, "\n");
  while (num != NULL) {
    mpz_set_str(dv.n, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.d, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.p, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.q, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.d_p, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.d_q, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.i_p, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.i_q, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.c, num, 16);
    num = strtok(NULL, "\n");

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

void elGamalEncrypt(ElGamalEncryptionVariables ev) {
  mpz_t c1;
  mpz_t c2;
  mpz_t r;
  mpz_t p_m, q_m, g_m, h_m, m_m, b, c1_m, c2_m, one, omega, rho;

  mpz_init(one);
  mpz_set_ui(one, 1ul);

  mpz_init(c1);
  mpz_init(c2);
  mpz_init(c1_m);
  mpz_init(c2_m);
  mpz_init(r);
  mpz_init(p_m);
  mpz_init(q_m);
  mpz_init(g_m);
  mpz_init(h_m);
  mpz_init(m_m);
  mpz_init(b);
  mpz_init(omega);
  mpz_init(rho);

  mpz_set_ui(b, 1ul);
  mpz_mul_2exp(b, b, mp_bits_per_limb);

  unsigned int size = 128;
  unsigned char seed[size];
  unsigned char random[size];
  int feedback = getSeed(size, seed);
  if (feedback != RDRAND_SUCCESS)
    fprintf(stderr, "Could not generate sufficiently random seed!\n");
  RAND_seed(seed, size);
  feedback = RAND_status();
  if (feedback != 1)
    fprintf(stderr, "Not enough random data in openSSL random library\n");
  do {
    feedback = RAND_bytes(random, size);
    if (feedback != 1) {
      fprintf(stderr, "PRNG not random enough.\n");
    }
    for (int i = 0; i < size; i = i + 8) {
      unsigned long temp = 0;
      for (int j = 0; j < 8; j++) {
        temp = temp << 8;
        temp = temp | random[i + j];
      }
      mpz_mul_2exp(r, r, 64ul); // Left shift to make space for more random data
      mpz_add_ui(r, r, temp); // Add random data to number
    }
  } while (mpz_cmp(ev.p, r) > 0 && mpz_cmp_ui(r, 1) >= 0);

  mpz_mont_rho_sq(rho, ev.p);
  mpz_mont_omega(omega, ev.p, b);
  mpz_mont_mul(g_m, ev.g, rho, ev.p, omega);
  mpz_mont_mul(h_m, ev.h, rho, ev.p, omega);
  mpz_mont_mul(m_m, ev.m, rho, ev.p, omega);

  mpz_sw_m(c1_m, g_m, r, ev.p, 4, omega, rho);
  mpz_sw_m(c2_m, h_m, r, ev.p, 4, omega, rho);
  mpz_mont_mul(c1, c1_m, one, ev.p, omega);
  mpz_mont_mul(c1_m, c2_m, m_m, ev.p, omega); // CAUTION: Resuing c1_m as a temp var
  mpz_mont_mul(c2, c1_m, one, ev.p, omega); // CAUTION: Resuing c1_m as a temp var

  gmp_printf("%ZX\n", c1);
  gmp_printf("%ZX\n", c2);

  mpz_clear(r);
  mpz_clear(c1);
  mpz_clear(c2);
  mpz_clear(c1_m);
  mpz_clear(c2_m);
  mpz_clear(g_m);
  mpz_clear(h_m);
  mpz_clear(m_m);
  mpz_clear(one);
  mpz_clear(omega);
  mpz_clear(rho);
  mpz_clear(p_m);
  mpz_clear(q_m);
  mpz_clear(b);
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

  char buffer[1024];
  size_t contentSize = 1;
  char * content = malloc(sizeof(char) * 1024);
  if (content == NULL) {
    fprintf(stderr, "Failed to allocated memory.\n");
    exit(1);
  }
  content[0] = '\0';
  while (fgets(buffer, 1024, stdin)) {
    contentSize += strlen(buffer);
    content = realloc(content, contentSize);
    if (content == NULL) {
      fprintf(stderr, "Failed to allocated memory.\n");
      free(content);
      exit(1);
    }
    strcat(content, buffer);
  }

  if (ferror(stdin)) {
    free(content);
    fprintf(stderr, "Error reading stdin.\n");
    exit(1);
  }

  char * num;
  num = strtok(content, "\n");
  while (num != NULL) {
    mpz_set_str(ev.p, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.q, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.g, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.h, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(ev.m, num, 16);
    num = strtok(NULL, "\n");

    elGamalEncrypt(ev);
  }

  mpz_clear(ev.p);
  mpz_clear(ev.q);
  mpz_clear(ev.g);
  mpz_clear(ev.h);
  mpz_clear(ev.m);
}

void elGamalDecrypt(ElGamalDecryptionVariables dv) {
  mpz_t m, omega, rho, b, c1_m, c2_m, e, m_m, temp, one;
  mpz_init(m);
  mpz_init(omega);
  mpz_init(rho);
  mpz_init(c1_m);
  mpz_init(c2_m);
  mpz_init(e);
  mpz_init(m_m);
  mpz_init(temp);
  mpz_init(one);
  mpz_init(b);
  mpz_set_ui(one, 1ul);
  mpz_set_ui(b, 1ul);
  mpz_mul_2exp(b, b, mp_bits_per_limb);

  mpz_mont_rho_sq(rho, dv.p);
  mpz_mont_omega(omega, dv.p, b);
  mpz_mont_mul(c1_m, dv.c1, rho, dv.p, omega);
  mpz_mont_mul(c2_m, dv.c2, rho, dv.p, omega);

  mpz_sub_ui(e, dv.p, 1ul);
  mpz_sub(e, e, dv.x);

  mpz_sw_m(temp, c1_m, e, dv.p, 4, omega, rho);

  mpz_mont_mul(m_m, temp, c2_m, dv.p, omega);
  mpz_mont_mul(m, m_m, one, dv.p, omega);

  gmp_printf("%ZX\n", m);
  mpz_clear(m);
  mpz_clear(omega);
  mpz_clear(rho);
  mpz_clear(c1_m);
  mpz_clear(c2_m);
  mpz_clear(e);
  mpz_clear(m_m);
  mpz_clear(temp);
  mpz_clear(one);
  mpz_clear(b);
}

/*
Perform stage 4:

- read each 5-tuple of p, q, g, x and c = (c_1,c_2) from stdin,
- compute the ElGamal decryption m, then
- write the plaintext m to stdout.
*/

void stage4() {
  ElGamalDecryptionVariables dv;

  mpz_init(dv.p);
  mpz_init(dv.q);
  mpz_init(dv.g);
  mpz_init(dv.x);
  mpz_init(dv.c1);
  mpz_init(dv.c2);

  char buffer[1024];
  size_t contentSize = 1;
  char * content = malloc(sizeof(char) * 1024);
  if (content == NULL) {
    fprintf(stderr, "Failed to allocated memory.\n");
    exit(1);
  }
  content[0] = '\0';
  while (fgets(buffer, 1024, stdin)) {
    contentSize += strlen(buffer);
    content = realloc(content, contentSize);
    if (content == NULL) {
      fprintf(stderr, "Failed to allocated memory.\n");
      free(content);
      exit(1);
    }
    strcat(content, buffer);
  }

  if (ferror(stdin)) {
    free(content);
    fprintf(stderr, "Error reading stdin.\n");
    exit(1);
  }

  char * num;
  num = strtok(content, "\n");
  while (num != NULL) {
    mpz_set_str(dv.p, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.q, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.g, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.x, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.c1, num, 16);
    num = strtok(NULL, "\n");

    if (num == NULL) {
      abort();
    }
    mpz_set_str(dv.c2, num, 16);
    num = strtok(NULL, "\n");

    elGamalDecrypt(dv);
  }

  mpz_clear(dv.p);
  mpz_clear(dv.q);
  mpz_clear(dv.g);
  mpz_clear(dv.x);
  mpz_clear(dv.c1);
  mpz_clear(dv.c2);
}

/*
The main function acts as a driver for the assignment by simply invoking
the correct function for the requested stage.
*/

int main(int argc, char * argv[]) {
  if (2 != argc) {
    abort();
  }

  if (!strcmp(argv[1], "stage1")) {
    stage1();
  } else if (!strcmp(argv[1], "stage2")) {
    stage2();
  } else if (!strcmp(argv[1], "stage3")) {
    stage3();
  } else if (!strcmp(argv[1], "stage4")) {
    stage4();
  } else {
    abort();
  }

  return 0;
}