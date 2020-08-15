//demo on how to apply boolean masking to SHA3
//don't use for production, this is only for educational purposes

#ifndef __SHA3_MASKED_H__
#define __SHA3_MASKED_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


void print_impl(const char*msg){printf("%s",msg);}
#include "print.h"
#include "assert_print.h"

#include "sha3_defs.h"

static void keccakf_theta_plain(uint64_t s[25]){
    int i, j;
    uint64_t t, bc[5];
    // Theta 
    for(i = 0; i < 5; i++)
        bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

    for(i = 0; i < 5; i++) {
        t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
        for(j = 0; j < 25; j += 5)
            s[j + i] ^= t;
    }
}

static void keccakf_rho_pi_plain(uint64_t s[25]){
    int i, j;
    uint64_t t, bc;
    // Rho Pi 
    t = s[1];
    for(i = 0; i < 24; i++) {
        j = keccakf_piln[i];
        bc = s[j];
        s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
        t = bc;
    }
}

static void keccakf_chi_plain(uint64_t s[25]){
    int i, j;
    uint64_t bc[5];
    // Chi 
    for(j = 0; j < 25; j += 5) {
        for(i = 0; i < 5; i++)
            bc[i] = s[j + i];
        for(i = 0; i < 5; i++)
            s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
}

static void keccakf_iota_plain(uint64_t s[25], int round){
    // Iota
    s[0] ^= keccakf_rndc[round];
}

static void keccakf_round_plain(uint64_t s[25], int round){
    keccakf_theta_plain(s);
    keccakf_rho_pi_plain(s);
    keccakf_chi_plain(s);
    keccakf_iota_plain(s, round);
}

static void keccakf_plain(uint64_t s[25]){
    for(int round = 0; round < KECCAK_ROUNDS; round++) {
        keccakf_round_plain(s, round);
    }
}

static void xor_buf(void*dst,const void*const a,const void*const b, size_t size){
    uint8_t *dst8 = (uint8_t*)dst;
    const uint8_t *const a8 = (const uint8_t*const)a;
    const uint8_t *const b8 = (const uint8_t*const)b;
    for(size_t i=0;i<size;i++){
        dst8[i] = a8[i]^b8[i];
    }
}

#define IMAX_BITS(m) ((m)/((m)%255+1) / 255%255*8 + 7-86/((m)%255+12))
#define RAND_MAX_WIDTH IMAX_BITS(RAND_MAX)
_Static_assert((RAND_MAX & (RAND_MAX + 1u)) == 0, "RAND_MAX not a Mersenne number");

uint64_t rand64(void) {
  uint64_t r = 0;
  for (int i = 0; i < 64; i += RAND_MAX_WIDTH) {
    r <<= RAND_MAX_WIDTH;
    r ^= (unsigned) rand();
  }
  return r;
}

static void and2_masked2(uint64_t dst[2],uint64_t a[2],uint64_t b[2]){
    //see and2 operation as a multiplication
    //(a0+a1)(b0+b1)=a0b0+a0b1+a1b0+a1b1
    uint64_t random = rand64(); // injection of random (random from PRNG)
    // random are mandatory, if 0 then output is biased:
    //
    // a b a&b a0 a1 b0 b1  a0b0 a0b1 a1b0 a1b1   a0b0+a0b1   a0b0+a1b1
    // 0 0  0  0  0  0  0     0    0    0    0        0           0 
    // 0 0  0  0  0  1  1     0    0    0    0        0           0
    // 0 0  0  1  1  0  0     0    0    0    0        0           0
    // 0 0  0  1  1  1  1     1    1    1    1        0           0
    // 0 1  0  0  0  0  1     0    0    0    0        0           0
    // 0 1  0  0  0  1  0     0    0    0    0        0           0
    // 0 1  0  1  1  0  1     0    1    0    1        1*          1*
    // 0 1  0  1  1  1  0     1    0    1    0        1*          1*
    // 1 0  0  0  1  0  0     0    0    0    0        0           0
    // 1 0  0  0  1  1  1     0    0    1    1        0           1 
    // 1 0  0  1  0  0  0     0    0    0    0        0           0
    // 1 0  0  1  0  1  1     1    1    0    0        0           1
    // 1 1  1  0  1  0  1     0    0    0    1        0           1*
    // 1 1  1  0  1  1  0     0    0    1    0        0           0
    // 1 1  1  1  0  0  1     0    1    0    0        1*          0
    // 1 1  1  1  0  1  0     1    0    0    0        1*          1*
    //
    // a0b0+a0b1: all the ones match b=1 cases
    // a0b0+a1b1: 4 ones out of 6 match b=1 cases
    dst[0] = (a[0] & b[0]) ^ ((a[0] & b[1]) ^ random);
    dst[1] = (a[1] & b[0]) ^ ((a[1] & b[1]) ^ random);
}

static void keccakf_theta_masked(uint64_t shares[2][25]){
    for(int si=0;si<2;si++){
        keccakf_theta_plain(shares[si]);
    }
}

static void keccakf_rho_pi_masked(uint64_t shares[2][25]){
    for(int si=0;si<2;si++){
        keccakf_rho_pi_plain(shares[si]);
    }
}

static void keccakf_chi_masked(uint64_t shares[2][25]){
    //xor_buf(shares[0],shares[0],shares[1],SHA3_STATE_SIZE);memset(shares[1],0,SHA3_STATE_SIZE);uint64_t*s=shares[0];
    int i, j;
    uint64_t bc[2][5];
    // Chi 
    for(j = 0; j < 25; j += 5) {
        for(i = 0; i < 5; i++){
            for(int si=0;si<2;si++){
                bc[si][i] = shares[si][j + i];
            }
        }
        for(i = 0; i < 5; i++){
            uint64_t ws[2],a[2],b[2];
            
            a[0] = ~bc[0][(i + 1) % 5];
            a[1] =  bc[1][(i + 1) % 5]; // no inversion, that would cancel out
            b[0] =  bc[0][(i + 2) % 5];
            b[1] =  bc[1][(i + 2) % 5];

            and2_masked2(ws,a,b);

            for(int si=0;si<2;si++){
                shares[si][j + i] ^= ws[si];
            }
        }
    }
}

static void keccakf_iota_masked(uint64_t shares[2][25], int round){
    keccakf_iota_plain(shares[0],round);
}

static void keccakf_round_masked(uint64_t shares[2][25], int round){
    keccakf_theta_masked(shares);
    keccakf_rho_pi_masked(shares);
    keccakf_chi_masked(shares);
    keccakf_iota_masked(shares, round);
}

static void keccakf_masked(uint64_t shares[2][25]){
    for(int round = 0; round < KECCAK_ROUNDS; round++) {
        keccakf_round_masked(shares, round);
    }
}

static void keccakf_masked_wrapper(uint64_t s[25]){
    uint64_t shares[2][25];
    for(int i=0;i<SHA3_STATE_WORDS;i++){
        shares[0][i]=rand64();
    }
    xor_buf(shares[1],shares[0],s,SHA3_STATE_SIZE);
    keccakf_masked(shares);
    xor_buf(s,shares[0],shares[1],SHA3_STATE_SIZE);
}

#endif
