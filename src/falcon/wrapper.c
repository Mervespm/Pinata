#include "wrapper.h"

// These includes MUST stay private to wrapper.c, otherwise we pollute the
// global namespace with equally named, but totally different files
// (api.h / inner.h) used by other ciphers.
// Note: we deliberately do NOT include/compile fndsa's own api.c, and thus
// never touch its crypto_sign_keypair()/crypto_sign()/crypto_sign_open()
// wrappers - those names collide with ML-DSA's identically-named functions
// in this same firmware image. fndsa.h exposes uniquely-prefixed functions
// instead, which is what we call directly below.
#include <fndsa.h>       // include is located in pqm4's fndsa_provisional-512/m4f
#include <randombytes.h> // include is located in src/pqm4_hal

#if FALCON_PUBLIC_KEY_SIZE != FNDSA_VRFY_KEY_SIZE(FNDSA_LOGN_512)
#error invalid public key size, update me!
#endif
#if FALCON_PRIVATE_KEY_SIZE != FNDSA_SIGN_KEY_SIZE(FNDSA_LOGN_512)
#error invalid private key size, update me!
#endif
#if FALCON_SIGNATURE_SIZE != FNDSA_SIGNATURE_SIZE(FNDSA_LOGN_512)
#error invalid signature size, update me!
#endif

uint8_t* FalconState_getPrivateKey(FalconState* self) {
	return self->m_sk;
}

uint8_t* FalconState_getPublicKey(FalconState* self) {
	return self->m_pk;
}

uint8_t* FalconState_getScratchPad(FalconState* self) {
	return self->m_scratchpad;
}

int FalconState_sign(FalconState* self, uint8_t* signature, const uint8_t* message) {
	// fndsa_sign_seeded() (rather than the _temp variant) allocates its
	// scratch buffer on the call stack instead of static RAM - the firmware
	// reserves a large stack for exactly this kind of transient use, whereas
	// static RAM is comparatively tight once ML-DSA/ML-KEM/Falcon all coexist.
	uint8_t seed[40];
	randombytes(seed, sizeof seed);
	size_t signatureLength = fndsa_sign_seeded(
	    self->m_sk, FALCON_PRIVATE_KEY_SIZE,
	    NULL, 0, FNDSA_HASH_ID_RAW, message, FALCON_MESSAGE_SIZE,
	    seed, sizeof seed,
	    signature, FALCON_SIGNATURE_SIZE);
	return signatureLength == FALCON_SIGNATURE_SIZE ? 0 : 1;
}

int FalconState_verify(FalconState* self, const uint8_t* signature, const uint8_t* message) {
	int valid = fndsa_verify(
	    signature, FALCON_SIGNATURE_SIZE,
	    self->m_pk, FALCON_PUBLIC_KEY_SIZE,
	    NULL, 0, FNDSA_HASH_ID_RAW, message, FALCON_MESSAGE_SIZE);
	return valid ? 0 : 1;
}
