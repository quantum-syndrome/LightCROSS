/**
 *
 * Reference ISO-C11 Implementation of CROSS.
 *
 * @version 2.0 (February 2025)
 *
 * Authors listed in alphabetical order:
 *
 * @author: Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author: Marco Gianvecchio <marco.gianvecchio@mail.polimi.it>
 * @author: Patrick Karl <patrick.karl@tum.de>
 * @author: Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author: Jonas Schupp <jonas.schupp@tum.de>
 *
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#pragma once
#include <stdint.h>

#include "constants.h"
#include "variant.h"

/******************************************************************************/
/**************************** Shared Optimisations ****************************/
/******************************************************************************/
//
#define SKIP_ASSERT
/*
 * Original Optimisations
 */
#define OPT_KEYGEN
//    Note this is overidden if OPT_OTF_MERKLE is defined
#define OPT_MERKLE
#define OPT_HASH_CMT1
#define OPT_HASH_Y
/*
 * New Optimisations
 */
// Note this is overidden if OPT_E_BAR_PRIME is defined
#define OPT_V_BAR
#define OPT_E_BAR_PRIME
#define OPT_OTF_MERKLE
#define OPT_GGM
//    The only ARM specific optimisation
#define OPT_DSP
#define OPT_Y_U_OVERLAP
#define OPT_KEYGEN_BLOCKS
//  Experimental - Flag not recommended
//  #define OPT_MERKLE_GGM_COMBO
/*
 * Debugging Flags
 */
// #define OPT_DEBUG
// #define OPT_PROFILE
//  #define DETERMINISTIC

/******************************************************************************/
/*************************** Base Fields Parameters ***************************/
/******************************************************************************/
#if defined(RSDP)

/* The same base field and restriction are employed for all categories of RSDP
 */
#define P (127)
#define Z (7)
/* single-register table representation of E, the value of g^7=1 is also
 * represented to avoid exponent renormalization*/
#define RESTR_G_TABLE ((uint64_t)(0x0140201008040201))
#define RESTR_G_GEN 2
#define FP_ELEM uint8_t
#define FZ_ELEM uint8_t
#define FP_DOUBLEPREC uint16_t
#define FP_TRIPLEPREC uint32_t
#elif defined(RSDPG)

/* The same base field and restriction are employed for all categories of RSDP
 */
#define P (509)
#define Z (127)
/* Restricted subgroup generator */
#define RESTR_G_GEN 16
#define FZ_ELEM uint8_t
#define FZ_DOUBLEPREC uint16_t
#define FP_ELEM uint16_t
#define FP_DOUBLEPREC uint32_t
#define FP_TRIPLEPREC uint32_t

#else
#error define either RSDP or RSDPG
#endif

/******************************************************************************/
/****************************** RSDP Parameters *******************************/
/******************************************************************************/
#if defined(RSDP)
/********************************* Category 1 *********************************/
#if defined(CATEGORY_1)
#define SEC_MARGIN_LAMBDA (128)
#define N (127)
#define K (76)

#if defined(SPEED)
#define T (157)
#define W (82)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(BALANCED)
#define T (256)
#define W (215)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(SIG_SIZE)
#define T (520)
#define W (488)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

/********************************* Category 3 *********************************/
#elif defined(CATEGORY_3)
#define SEC_MARGIN_LAMBDA (192)
#define N (187)
#define K (111)

#if defined(SPEED)
#define T (239)
#define W (125)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(BALANCED)
#define T (384)
#define W (321)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(SIG_SIZE)
#define T (580)
#define W (527)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

/********************************* Category 5 *********************************/
#elif defined(CATEGORY_5)
#define SEC_MARGIN_LAMBDA (256)
#define N (251)
#define K (150)

#if defined(SPEED)
#define T (321)
#define W (167)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(BALANCED)
#define T (512)
#define W (427)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(SIG_SIZE)
#define T (832)
#define W (762)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

#else
#error define category for parameters
#endif

/******************************************************************************/
/****************************** RSDP(G) Parameters ****************************/
/******************************************************************************/
#elif defined(RSDPG)
/********************************* Category 1 *********************************/
#if defined(CATEGORY_1)
#define SEC_MARGIN_LAMBDA (128)
#define N (55)
#define K (36)
#define RSDPG_M (25)

#if defined(SPEED)
#define T (147)
#define W (76)
#define POSITION_IN_FW_STRING_T uint8_t
#elif defined(BALANCED)
#define T (256)
#define W (220)
#define POSITION_IN_FW_STRING_T uint8_t
#elif defined(SIG_SIZE)
#define T (512)
#define W (484)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

/********************************* Category 3 *********************************/
#elif defined(CATEGORY_3)
#define SEC_MARGIN_LAMBDA (192)
#define N (79)
#define K (48)
#define RSDPG_M (40)

#if defined(SPEED)
#define T (224)
#define W (119)
#define POSITION_IN_FW_STRING_T uint8_t
#elif defined(BALANCED)
#define T (268)
#define W (196)
#define POSITION_IN_FW_STRING_T uint8_t
#elif defined(SIG_SIZE)
#define T (512)
#define W (463)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

/********************************* Category 5 *********************************/
#elif defined(CATEGORY_5)
#define SEC_MARGIN_LAMBDA (256)
#define N (106)
#define K (69)
#define RSDPG_M (48)

#if defined(SPEED)
#define T (300)
#define W (153)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(BALANCED)
#define T (356)
#define W (258)
#define POSITION_IN_FW_STRING_T uint16_t
#elif defined(SIG_SIZE)
#define T (642)
#define W (575)
#define POSITION_IN_FW_STRING_T uint16_t

#else
#error define optimization corner in Cmakelist
#endif

#else
#error define category for parameters
#endif

#else
#error define either RSDP or RSDPG
#endif

#define CSPRNG_DOMAIN_SEP_CONST ((uint16_t)0)
#define HASH_DOMAIN_SEP_CONST ((uint16_t)32768)

/************* Helper macros for derived parameter computation ***************/

#define ROUND_UP(amount, round_amt)                                            \
  (((amount + round_amt - 1) / round_amt) * round_amt)

#define IS_REPRESENTABLE_IN_D_BITS(D, N)                                       \
  (((unsigned long)N >= (1UL << (D - 1)) && (unsigned long)N < (1UL << D))     \
       ? D                                                                     \
       : -1)

#define BITS_TO_REPRESENT(N)                                                   \
  (N == 0 ? 1                                                                  \
          : (15 + IS_REPRESENTABLE_IN_D_BITS(1, N) +                           \
             IS_REPRESENTABLE_IN_D_BITS(2, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(3, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(4, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(5, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(6, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(7, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(8, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(9, N) +                                \
             IS_REPRESENTABLE_IN_D_BITS(10, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(11, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(12, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(13, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(14, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(15, N) +                               \
             IS_REPRESENTABLE_IN_D_BITS(16, N)))

// NOTE: This is ceil(log_2(N))
#define LOG2(L)                                                                \
  ((BITS_TO_REPRESENT(L) > BITS_TO_REPRESENT(L - 1))                           \
       ? (BITS_TO_REPRESENT(L - 1))                                            \
       : (BITS_TO_REPRESENT(L)))

/***************** Derived parameters *****************************************/
#define SEED_LENGTH_BYTES (SEC_MARGIN_LAMBDA / 8)
#define KEYPAIR_SEED_LENGTH_BYTES (2 * (SEC_MARGIN_LAMBDA / 8))
#define HASH_DIGEST_LENGTH (2 * (SEC_MARGIN_LAMBDA / 8))
#define SALT_LENGTH_BYTES (2 * (SEC_MARGIN_LAMBDA / 8))

#define NUM_LEAVES_MERKLE_TREE (T)
#define NUM_NODES_MERKLE_TREE (2 * NUM_LEAVES_MERKLE_TREE - 1)

#define NUM_LEAVES_SEED_TREE (T)
#define NUM_NODES_SEED_TREE (2 * NUM_LEAVES_SEED_TREE - 1)

/* Sizes of bitpacked field element vectors
 * Bitpacking an n-elements vector of num_bits_for_q-1 bits long values
 * will pack 8 values in num_bits_for_q-1 bytes exactly, leaving the remaining
 * N % 8 as a tail */
#define DENSELY_PACKED_FP_VEC_SIZE                                             \
  ((N / 8) * BITS_TO_REPRESENT(P - 1) +                                        \
   ROUND_UP(((N % 8) * BITS_TO_REPRESENT(P - 1)), 8) / 8)
#define DENSELY_PACKED_FP_SYN_SIZE                                             \
  (((N - K) / 8) * BITS_TO_REPRESENT(P - 1) +                                  \
   ROUND_UP((((N - K) % 8) * BITS_TO_REPRESENT(P - 1)), 8) / 8)
#define DENSELY_PACKED_FZ_VEC_SIZE                                             \
  ((N / 8) * BITS_TO_REPRESENT(Z - 1) +                                        \
   ROUND_UP(((N % 8) * BITS_TO_REPRESENT(Z - 1)), 8) / 8)
#ifdef RSDPG
#define DENSELY_PACKED_FZ_RSDP_G_VEC_SIZE                                      \
  ((RSDPG_M / 8) * BITS_TO_REPRESENT(Z - 1) +                                  \
   ROUND_UP(((RSDPG_M % 8) * BITS_TO_REPRESENT(Z - 1)), 8) / 8)
#endif
