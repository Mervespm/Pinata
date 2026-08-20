#ifndef _FALCON_WRAPPER_H_
#define _FALCON_WRAPPER_H_

#include <stdint.h>
#include <stddef.h>

// FN-DSA (FIPS 206), degree 512, i.e. what used to be called "Falcon-512".
// Sizes below match pqm4's crypto_sign/fndsa_provisional-512/m4f/api.h
// (FNDSA_VRFY_KEY_SIZE(9), FNDSA_SIGN_KEY_SIZE(9), FNDSA_SIGNATURE_SIZE(9)).
// The signature is fixed-size (no variable-length framing), which fits
// Pinata's fixed-size request/response protocol - the same reason ML-DSA
// (rather than a variable-length scheme) was chosen.
#define FALCON_PUBLIC_KEY_SIZE 897
#define FALCON_PRIVATE_KEY_SIZE 1281
#define FALCON_SIGNATURE_SIZE 666
#define FALCON_MESSAGE_SIZE 16
#define FALCON_SIGNED_MESSAGE_SIZE (FALCON_SIGNATURE_SIZE + FALCON_MESSAGE_SIZE)

/**
 * Simple object-oriented wrapper around the various Falcon (FN-DSA) functions.
 * All "methods" start with the prefix "FalconState_".
 */
typedef struct FalconState_t {
	uint8_t m_pk[FALCON_PUBLIC_KEY_SIZE];
	uint8_t m_sk[FALCON_PRIVATE_KEY_SIZE];
	uint8_t m_scratchpad[FALCON_SIGNED_MESSAGE_SIZE];
} FalconState;

/**
 * @brief      Get the private key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The private key bytes.
 */
uint8_t* FalconState_getPrivateKey(FalconState* self);

/**
 * @brief      Get the public key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The public key bytes.
 */
uint8_t* FalconState_getPublicKey(FalconState* self);

/**
 * @brief      Get the "scratch pad" for message storage, signature storage.
 *
 * @param      self  The object
 *
 * @return     Pointer to the scratch pad.
 */
uint8_t* FalconState_getScratchPad(FalconState* self);

/**
 * @brief      Sign a message.
 *
 * @param[in]  self           The object
 * @param[out] signature      Buffer where the signature will be placed in. This
 *                            buffer MUST have length FALCON_SIGNATURE_SIZE.
 * @param[in]  message        Buffer of the message to be signed. This buffer MUST
 *                            have length FALCON_MESSAGE_SIZE.
 *
 * @return     0 when signing succeeds, non-zero otherwise.
 */
int FalconState_sign(FalconState* self, uint8_t* signature, const uint8_t* message);

/**
 * @brief      Verify a detached signature over a message.
 *
 * @param[in]  self           The object
 * @param[in]  signature      Buffer of the signature. This buffer MUST have
 *                            length FALCON_SIGNATURE_SIZE.
 * @param[in]  message        Buffer of the signed message. This buffer MUST
 *                            have length FALCON_MESSAGE_SIZE.
 *
 * @return     0 when verification passes, non-zero otherwise.
 */
int FalconState_verify(FalconState* self, const uint8_t* signature, const uint8_t* message);

#endif // _FALCON_WRAPPER_H_
