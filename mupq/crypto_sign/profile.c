// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
#include "api.h"
#include "hal.h"
#include "sendfn.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MLEN 59
// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_BYTES NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign NAMESPACE(crypto_sign)
#define MUPQ_crypto_sign_open NAMESPACE(crypto_sign_open)
#define MUPQ_crypto_sign_signature NAMESPACE(crypto_sign_signature)
#define MUPQ_crypto_sign_verify NAMESPACE(crypto_sign_verify)

#define printcycles(S, U) send_unsignedll((S), (U))

// unsigned long long hash_cycles;
uint64_t fp_arith_cycles;
uint64_t restr_arith_cycles;
uint64_t csprng_cycles;
uint64_t hash_cycles;

int main(void) {
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sm[MLEN + MUPQ_CRYPTO_BYTES];
  size_t smlen;
  unsigned long long t0, t1;
  int i;

  hal_setup(CLOCK_BENCHMARK);

  hal_send_str("==========================");

  for (i = 0; i < MUPQ_ITERATIONS; i++) {
    // Key-pair generation
    //    hash_cycles = 0;
    fp_arith_cycles = 0;
    restr_arith_cycles = 0;
    t0 = hal_get_time();
    MUPQ_crypto_sign_keypair(pk, sk);
    t1 = hal_get_time();
    //    printcycles("keypair hash cycles:", hash_cycles);
    printcycles("keypair fp_arith cycles:", fp_arith_cycles);
    printcycles("keypair restr_arith cycles:", restr_arith_cycles);
    printcycles("keypair csprng cycles:", csprng_cycles);
    printcycles("keypair hash cycles:", hash_cycles);
    printcycles("keypair total cycles:", t1 - t0);
    // hal_send_str("+");

    // Signing
    //    hash_cycles = 0;
    fp_arith_cycles = 0;
    t0 = hal_get_time();
    MUPQ_crypto_sign(sm, &smlen, sm, MLEN, sk);
    t1 = hal_get_time();
    //   printcycles("sign hash cycles:", hash_cycles);
    printcycles("sign fp_arith cycles:", fp_arith_cycles);
    printcycles("sign restr_arith cycles:", restr_arith_cycles);
    printcycles("sign csprng cycles:", csprng_cycles);
    printcycles("sign hash cycles:", hash_cycles);
    printcycles("sign total cycles:", t1 - t0);
    // hal_send_str("+");

    // Verification
    //   hash_cycles = 0;
    fp_arith_cycles = 0;
    t0 = hal_get_time();
    MUPQ_crypto_sign_open(sm, &smlen, sm, smlen, pk);
    t1 = hal_get_time();
    //    printcycles("verify hash cycles:", hash_cycles);
    printcycles("verify fp_arith cycles:", fp_arith_cycles);
    printcycles("verify restr_arith cycles:", restr_arith_cycles);
    printcycles("verify csprng cycles:", csprng_cycles);
    printcycles("verify hash cycles:", hash_cycles);
    printcycles("verify total cycles:", t1 - t0);

    hal_send_str("+");
  }

  hal_send_str("#");
  return 0;
}
