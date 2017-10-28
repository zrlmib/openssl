/* crypto/oqs/oqs.h */

#ifndef HEADER_OQS_H
#define HEADER_OQS_H

#ifdef OPENSSL_NO_OQS
#error OQS is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Define OQS signature algorithms.
 */
#define NID_oqs_picnic_default 958


/* Adds the OQS algorithm. Should be called after add OPENSSL_add_all_algorithms */
void OQS_add_all_algorithms();

/* Shuts down OQS */
void OQS_shutdown();

#ifdef  __cplusplus
}
#endif

#endif
