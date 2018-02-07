/* crypto/oqs/oqs_sig.h */

#ifndef HEADER_SIG_OQS_H
#define HEADER_SIG_OQS_H

#ifdef OPENSSL_NO_OQS
#error OQS is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Define OQS signature algorithms.
 * FIXME: we shouldn't hardcode these values. These values that will be assigned
 *        in OQS_add_all_algorithms, by incrementing NUM_NID (from obj_dat.h)
 */
#define NID_oqs_picnic_default 958
// #define NID_oqs_... (other OQS algs)
  
/* Adds the OQS algorithm. Should be called after add OPENSSL_add_all_algorithms */
int OQS_add_all_algorithms();

/* Shuts down OQS. */
int OQS_shutdown();

#ifdef  __cplusplus
}
#endif

#endif

