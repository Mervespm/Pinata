/*
 * host_keygen: generates N *valid* FN-DSA-512 (Falcon-512) keypairs on the
 * host PC, using the exact same portable-C keygen/codec algorithm that runs
 * on the Pinata board (see fndsa/ in this directory - a frozen copy of
 * Pinata/build/_deps/pqm4-src/crypto_sign/fndsa_provisional-512/m4f, minus
 * the Cortex-M4 assembly).
 *
 * This exists because a profiled (template) side-channel attack needs many
 * *known* keys: for each key we also decode and dump the raw f/g secret
 * coefficient arrays (ground truth for the trim_i8_decode() leakage the
 * Pinata GPIO trigger brackets), so the profiling stage can label each
 * trace with the true coefficient values it should be learning to recover.
 *
 * The all-zero placeholder key in inspector-scripts/falcon_sca_pinata.py
 * is not a valid encoded key (byte 0 must be 0x59 for logn=9) and every
 * sign attempt against it fails - this tool is what replaces it.
 *
 * Output: two files next to each other,
 *   <prefix>.bin       - back-to-back fixed-size records, one per key:
 *                         pk (897B) || sk (1281B) || f (512B, int8) || g (512B, int8)
 *   <prefix>.meta.json - record count/size/offsets, so the Python loader
 *                         doesn't have to hardcode the layout blindly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "fndsa/fndsa.h"
#include "fndsa/inner.h"

#define LOGN 9u
#define N_COEFFS (1u << LOGN)
#define SK_SIZE FNDSA_SIGN_KEY_SIZE(LOGN)
#define PK_SIZE FNDSA_VRFY_KEY_SIZE(LOGN)
#define FG_NBITS 6u /* max_fg_bits for logn=9: f and g are packed 6 bits/coeff */

static int decode_fg(const uint8_t *sk, int8_t *f, int8_t *g) {
	/* Mirrors fndsa/sign.c's sign_step1(): byte 0 is a header, then f and g
	   are each trim_i8_decode()'d with FG_NBITS; F follows but we don't
	   need it here. */
	size_t j = 1;
	size_t k = trim_i8_decode(LOGN, sk + j, f, FG_NBITS);
	if (k == 0) {
		return 0;
	}
	j += k;
	k = trim_i8_decode(LOGN, sk + j, g, FG_NBITS);
	if (k == 0) {
		return 0;
	}
	return 1;
}

/*
 * Rebuild a private key encoding that is identical to base_sk except that
 * coefficient f[coeff_index] has been changed to `value`. Only f's packed
 * region can differ (g and F, and the header byte, are copied verbatim) -
 * and in practice only ONE byte of that region actually changes, since
 * trim_i8_encode() packs 4 coefficients into 3 bytes and every OTHER
 * coefficient is unchanged. This is what makes a single-coefficient sweep
 * a clean one-variable change instead of "63 more independent keys".
 *
 * Signing never checks that f/g/F/G satisfy the NTRU equation as a group -
 * G isn't even stored in the key, it's recomputed fresh from f, g, F on
 * every sign() call (see fndsa/sign.c's sign_step1(), lines computing
 * h=g/f then G=h*F). So perturbing only f[coeff_index] against an
 * otherwise-untouched, real, valid base key is safe: signing will succeed
 * for it exactly as long as the (still almost-certainly-invertible)
 * perturbed f is invertible mod q, same as for any other valid key.
 */
static int build_variant_sk(const uint8_t *base_sk, uint8_t *out_sk,
	const int8_t *base_f, unsigned coeff_index, int value)
{
	memcpy(out_sk, base_sk, SK_SIZE);
	int8_t f_variant[N_COEFFS];
	memcpy(f_variant, base_f, sizeof f_variant);
	f_variant[coeff_index] = (int8_t)value;
	size_t f_packed_len = ((size_t)FG_NBITS << LOGN) >> 3; /* 384 for logn=9 */
	uint8_t packed[384];
	if (trim_i8_encode(LOGN, f_variant, FG_NBITS, packed) != f_packed_len) {
		return 0;
	}
	memcpy(out_sk + 1, packed, f_packed_len);
	return 1;
}

static int run_sweep(unsigned coeff_index, const char *prefix) {
	if (coeff_index >= N_COEFFS) {
		fprintf(stderr, "coeff_index must be in 0..%u\n", N_COEFFS - 1);
		return 1;
	}

	uint8_t base_sk[SK_SIZE], base_pk[PK_SIZE];
	if (!fndsa_keygen(LOGN, base_sk, base_pk)) {
		fprintf(stderr, "fndsa_keygen() failed (OS RNG error)\n");
		return 1;
	}
	int8_t base_f[N_COEFFS], base_g[N_COEFFS];
	if (!decode_fg(base_sk, base_f, base_g)) {
		fprintf(stderr, "failed to decode f/g from the freshly generated base key\n");
		return 1;
	}

	char bin_path[512], meta_path[512];
	snprintf(bin_path, sizeof bin_path, "%s.bin", prefix);
	snprintf(meta_path, sizeof meta_path, "%s.meta.json", prefix);
	FILE *bin = fopen(bin_path, "wb");
	if (!bin) {
		fprintf(stderr, "failed to open %s for writing\n", bin_path);
		return 1;
	}

	long written = 0;
	for (int value = -31; value <= 31; value++) {
		uint8_t sk_variant[SK_SIZE];
		if (!build_variant_sk(base_sk, sk_variant, base_f, coeff_index, value)) {
			fprintf(stderr, "value %d: re-encode failed, skipping\n", value);
			continue;
		}
		/* Round-trip check: decode the variant back and confirm f[coeff_index]
		   really is `value`, and every other coefficient is untouched. */
		int8_t f_check[N_COEFFS], g_check[N_COEFFS];
		if (!decode_fg(sk_variant, f_check, g_check) || f_check[coeff_index] != (int8_t)value) {
			fprintf(stderr, "value %d: round-trip check failed, skipping\n", value);
			continue;
		}
		for (unsigned i = 0; i < N_COEFFS; i++) {
			if (i != coeff_index && (f_check[i] != base_f[i] || g_check[i] != base_g[i])) {
				fprintf(stderr, "value %d: unexpected coefficient drift at index %u (bug!), skipping\n", value, i);
				goto skip;
			}
		}

		if (fwrite(base_pk, 1, PK_SIZE, bin) != PK_SIZE ||
		    fwrite(sk_variant, 1, SK_SIZE, bin) != SK_SIZE ||
		    fwrite(f_check, 1, N_COEFFS, bin) != N_COEFFS ||
		    fwrite(base_g, 1, N_COEFFS, bin) != N_COEFFS) {
			fprintf(stderr, "value %d: short write to %s\n", value, bin_path);
			fclose(bin);
			return 1;
		}
		written++;
skip:
		;
	}
	fclose(bin);

	size_t record_size = (size_t)PK_SIZE + SK_SIZE + N_COEFFS + N_COEFFS;
	FILE *meta = fopen(meta_path, "w");
	if (!meta) {
		fprintf(stderr, "failed to open %s for writing\n", meta_path);
		return 1;
	}
	fprintf(meta,
		"{\n"
		"  \"logn\": %u,\n"
		"  \"n_coeffs\": %u,\n"
		"  \"num_keys\": %ld,\n"
		"  \"record_size\": %zu,\n"
		"  \"sweep_coeff_index\": %u,\n"
		"  \"fields\": {\n"
		"    \"pk\":     { \"offset\": 0, \"size\": %u },\n"
		"    \"sk\":     { \"offset\": %u, \"size\": %u },\n"
		"    \"f\":      { \"offset\": %u, \"size\": %u, \"dtype\": \"int8\" },\n"
		"    \"g\":      { \"offset\": %u, \"size\": %u, \"dtype\": \"int8\" }\n"
		"  }\n"
		"}\n",
		LOGN, N_COEFFS, written, record_size, coeff_index,
		(unsigned)PK_SIZE,
		(unsigned)PK_SIZE, (unsigned)SK_SIZE,
		(unsigned)(PK_SIZE + SK_SIZE), N_COEFFS,
		(unsigned)(PK_SIZE + SK_SIZE + N_COEFFS), N_COEFFS);
	fclose(meta);

	fprintf(stderr, "wrote %ld f[%u]-sweep variants (of one fixed base key; g/F/pk identical "
		"across all of them) to %s (%s)\n", written, coeff_index, bin_path, meta_path);
	return written > 0 ? 0 : 1;
}

int main(int argc, char **argv) {
	if (argc >= 2 && strcmp(argv[1], "sweep") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"usage: %s sweep <coeff_index> [output_prefix=falcon_sweep]\n"
				"generates one base key, then all 63 valid variants of\n"
				"f[coeff_index] (everything else held fixed: g, F, pk).\n",
				argv[0]);
			return 1;
		}
		unsigned coeff_index = (unsigned)strtoul(argv[2], NULL, 10);
		const char *sweep_prefix = argc >= 4 ? argv[3] : "falcon_sweep";
		return run_sweep(coeff_index, sweep_prefix);
	}

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <num_keys> [output_prefix=falcon_keys]\n"
			"       %s sweep <coeff_index> [output_prefix=falcon_sweep]\n"
			"generates <num_keys> independent valid FN-DSA-512 keypairs (for a\n"
			"full joint-recovery attack), or a single-coefficient sweep (63\n"
			"variants of one base key, for profiling one coefficient first).\n",
			argv[0], argv[0]);
		return 1;
	}
	long num_keys = strtol(argv[1], NULL, 10);
	if (num_keys <= 0) {
		fprintf(stderr, "num_keys must be a positive integer\n");
		return 1;
	}
	const char *prefix = argc >= 3 ? argv[2] : "falcon_keys";

	char bin_path[512], meta_path[512];
	snprintf(bin_path, sizeof bin_path, "%s.bin", prefix);
	snprintf(meta_path, sizeof meta_path, "%s.meta.json", prefix);

	FILE *bin = fopen(bin_path, "wb");
	if (!bin) {
		fprintf(stderr, "failed to open %s for writing\n", bin_path);
		return 1;
	}

	uint8_t sk[SK_SIZE];
	uint8_t pk[PK_SIZE];
	int8_t f[N_COEFFS];
	int8_t g[N_COEFFS];

	long written = 0;
	for (long i = 0; i < num_keys; i++) {
		if (!fndsa_keygen(LOGN, sk, pk)) {
			fprintf(stderr, "key %ld: fndsa_keygen() failed (OS RNG error), stopping\n", i);
			break;
		}
		if (!decode_fg(sk, f, g)) {
			fprintf(stderr, "key %ld: failed to decode f/g from freshly generated key (bug?), skipping\n", i);
			continue;
		}
		if (sk[0] != (uint8_t)(0x50u + LOGN)) {
			fprintf(stderr, "key %ld: unexpected sk[0]=0x%02x (expected 0x%02x)\n",
				i, sk[0], 0x50u + LOGN);
		}

		if (fwrite(pk, 1, PK_SIZE, bin) != PK_SIZE ||
		    fwrite(sk, 1, SK_SIZE, bin) != SK_SIZE ||
		    fwrite(f, 1, N_COEFFS, bin) != N_COEFFS ||
		    fwrite(g, 1, N_COEFFS, bin) != N_COEFFS) {
			fprintf(stderr, "key %ld: short write to %s\n", i, bin_path);
			fclose(bin);
			return 1;
		}
		written++;
		if (written % 100 == 0 || written == num_keys) {
			fprintf(stderr, "generated %ld/%ld keys\r", written, num_keys);
		}
	}
	fclose(bin);
	fprintf(stderr, "\n");

	size_t record_size = (size_t)PK_SIZE + SK_SIZE + N_COEFFS + N_COEFFS;
	FILE *meta = fopen(meta_path, "w");
	if (!meta) {
		fprintf(stderr, "failed to open %s for writing\n", meta_path);
		return 1;
	}
	fprintf(meta,
		"{\n"
		"  \"logn\": %u,\n"
		"  \"n_coeffs\": %u,\n"
		"  \"num_keys\": %ld,\n"
		"  \"record_size\": %zu,\n"
		"  \"fields\": {\n"
		"    \"pk\":     { \"offset\": 0, \"size\": %u },\n"
		"    \"sk\":     { \"offset\": %u, \"size\": %u },\n"
		"    \"f\":      { \"offset\": %u, \"size\": %u, \"dtype\": \"int8\" },\n"
		"    \"g\":      { \"offset\": %u, \"size\": %u, \"dtype\": \"int8\" }\n"
		"  }\n"
		"}\n",
		LOGN, N_COEFFS, written, record_size,
		(unsigned)PK_SIZE,
		(unsigned)PK_SIZE, (unsigned)SK_SIZE,
		(unsigned)(PK_SIZE + SK_SIZE), N_COEFFS,
		(unsigned)(PK_SIZE + SK_SIZE + N_COEFFS), N_COEFFS);
	fclose(meta);

	fprintf(stderr, "wrote %ld keys to %s (%s)\n", written, bin_path, meta_path);
	return 0;
}
