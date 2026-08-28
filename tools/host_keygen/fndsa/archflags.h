/* Host-build override of the firmware's archflags.h.
 *
 * The original Pinata/src/falcon build forces FNDSA_ASM_CORTEXM4=1 to use
 * the Cortex-M4 assembly routines (mq_cm4.s, sha3_cm4.s, sign_fpr_cm4.s,
 * sign_sampler_cm4.s, codec_cm4.s). Those .s files are ARMv7E-M/DSP only
 * and cannot be assembled for a desktop host. This copy of the fndsa
 * sources (see README.md in this directory) is compiled with the plain,
 * portable C fallback path instead - same algorithm, no ASM.
 */
#define FNDSA_ASM_CORTEXM4 0
