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

#include "hal.h"
#include "parameters.h"

#if defined(OPT_DSP)
// #include "arm_math.h"
#include "cmsis_gcc.h"
#endif

#if defined(OPT_PROFILE)
extern uint64_t restr_arith_cycles;
#endif

#if defined(RSDP)
#define FZRED_SINGLE(x) (((x) & 0x07) + ((x) >> 3))
#define FZRED_OPPOSITE(x) ((x) ^ 0x07)
#define FZ_DOUBLE_ZERO_NORM(x) (((x) + (((x) + 1) >> 3)) & 0x07)

#elif defined(RSDPG)
#define FZRED_SINGLE(x) (((x) & 0x7f) + ((x) >> 7))
#define FZRED_DOUBLE(x) FZRED_SINGLE(FZRED_SINGLE(x))
#define FZRED_OPPOSITE(x) ((x) ^ 0x7f)
#define FZ_DOUBLE_ZERO_NORM(x) (((x) + (((x) + 1) >> 7)) & 0x7f)
#endif

static inline void fz_dz_norm_n(FZ_ELEM v[N]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  for (int i = 0; i < N; i++) {
    v[i] = FZ_DOUBLE_ZERO_NORM(v[i]);
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
}

/* Elements of the restricted subgroups are represented as the exponents of
 * the generator */
static inline void fz_vec_sub_n(FZ_ELEM res[N], const FZ_ELEM a[N],
                                const FZ_ELEM b[N]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  for (int i = 0; i < N; i++) {
    res[i] = FZRED_SINGLE(a[i] + FZRED_OPPOSITE(b[i]));
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
}

static inline int is_fz_vec_in_restr_group_n(const FZ_ELEM in[N]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  int is_in_ok = 1;
  for (int i = 0; i < N; i++) {
    is_in_ok = is_in_ok && (in[i] < Z);
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
  return is_in_ok;
}

#if defined(RSDPG)
/* computes the information word * M_G product to obtain an element of G
 * only non systematic portion of M_G = [W I] is used, transposed to improve
 * cache friendliness */
#if defined(OPT_DSP)
static void fz_inf_w_by_fz_matrix(FZ_ELEM res[N], const FZ_ELEM e[RSDPG_M],
                                  FZ_ELEM W_mat[N - RSDPG_M][RSDPG_M]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  memset(res, 0, (N - RSDPG_M) * sizeof(FZ_ELEM));
  memcpy(res + (N - RSDPG_M), e, RSDPG_M * sizeof(FZ_ELEM));
  for (int j = 0; j < N - RSDPG_M; j++) {
    uint64_t col_accum = 0;
    int i = 0;
    for (; i < RSDPG_M - 3; i += 4) {
      uint32_t e_val = *((uint32_t *)&e[i]);
      uint32_t W_mat_val = *((uint32_t *)&W_mat[j][i]);
      // Extract value e[i+1], e[i+3], V_tr[i+1], V_tr[i+3]
      uint32_t bottom_e = __UXTB16(e_val);
      uint32_t bottom_W_mat = __UXTB16(W_mat_val);
      // Extract value e[i], e[i+2], V_tr[i], V_tr[i+2]
      uint32_t top_e = __UXTB16(__ROR(e_val, 8));
      uint32_t top_W_mat = __UXTB16(__ROR(W_mat_val, 8));
      // Calculate
      col_accum = __SMLALD(bottom_e, bottom_W_mat, col_accum);
      col_accum = __SMLALD(top_e, top_W_mat, col_accum);
    }
    //  finish remaining
    for (; i < RSDPG_M; i++) {
      // col_accum = FZRED_DOUBLE(
      //     col_accum + ((FZ_DOUBLEPREC)e[i] * (FZ_DOUBLEPREC)W_mat[j][i]));
      col_accum += ((FZ_DOUBLEPREC)e[i] * (FZ_DOUBLEPREC)W_mat[j][i]);
    }
    // This should work because the max value of M * FZ_ELEM x FZ_ELEM
    // multiplications is 0xBD030 or 20 bits. So 3 reductions covers
    // 3 bytes.
    col_accum = FZRED_SINGLE(FZRED_DOUBLE(col_accum));
    // Store and reduce modulo P
    res[j] = FZRED_DOUBLE(((uint64_t)res[j] + col_accum));
  }
#else
static void fz_inf_w_by_fz_matrix(FZ_ELEM res[N], const FZ_ELEM e[RSDPG_M],
                                  FZ_ELEM W_mat[RSDPG_M][N - RSDPG_M]) {

#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  memset(res, 0, (N - RSDPG_M) * sizeof(FZ_ELEM));
  memcpy(res + (N - RSDPG_M), e, RSDPG_M * sizeof(FZ_ELEM));
  for (int i = 0; i < RSDPG_M; i++) {
    for (int j = 0; j < N - RSDPG_M; j++) {
      res[j] = FZRED_DOUBLE((FZ_DOUBLEPREC)res[j] +
                            (FZ_DOUBLEPREC)e[i] * (FZ_DOUBLEPREC)W_mat[i][j]);
    }
  }
#endif
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
}

static inline void fz_vec_sub_m(FZ_ELEM res[RSDPG_M], const FZ_ELEM a[RSDPG_M],
                                const FZ_ELEM b[RSDPG_M]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  for (int i = 0; i < RSDPG_M; i++) {
    res[i] = FZRED_SINGLE(a[i] + FZRED_OPPOSITE(b[i]));
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
}

static inline int is_fz_vec_in_restr_group_m(const FZ_ELEM in[RSDPG_M]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  int is_in_ok = 1;
  for (int i = 0; i < RSDPG_M; i++) {
    is_in_ok = is_in_ok && (in[i] < Z);
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
  return is_in_ok;
}
static inline void fz_dz_norm_m(FZ_ELEM v[RSDPG_M]) {
#if defined(OPT_PROFILE)
  uint64_t t0 = hal_get_time();
#endif
  for (int i = 0; i < RSDPG_M; i++) {
    v[i] = FZ_DOUBLE_ZERO_NORM(v[i]);
  }
#if defined(OPT_PROFILE)
  uint64_t t1 = hal_get_time();
  restr_arith_cycles += t1 - t0;
#endif
}
#endif
