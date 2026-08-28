"""Incremental (streaming) first-round CPA against software AES-128 on the
Pinata board, one key byte at a time - 16 independent attackers running in
parallel, all fed the same trace.

The correlation math (running sums -> Pearson rho, same formula, same
online-update style) is adapted from MLDSA-SCA/SCA_scripts/CW305/CPACalc.py;
the leakage model (HW(Sbox[plaintext_byte ^ keyguess])) is adapted from
SCA_methods.py's CPAonAESonPlaintext, generalized from "byte 0 only" to all
16 key bytes running side by side.
"""
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
_HW_TABLE = np.array([bin(x).count("1") for x in range(256)], dtype=np.float64)
# hw_leak[keyguess, plaintext_byte] = HW(Sbox[plaintext_byte ^ keyguess]) - precomputed once.
_LEAK_TABLE = np.array(
    [[_HW_TABLE[SBOX[kg ^ pt]] for pt in range(256)] for kg in range(256)], dtype=np.float64
)


class AESByteCPA:
    """Incremental first-order CPA for ONE AES-128 key byte position.
    256 key-byte hypotheses x num_samples running correlation sums."""

    def __init__(self, num_samples: int):
        self.num_samples = num_samples
        self.n = 0
        self.sum_h = np.zeros(256, dtype=np.float64)
        self.sum_h2 = np.zeros(256, dtype=np.float64)
        self.sum_t = np.zeros(num_samples, dtype=np.float64)
        self.sum_t2 = np.zeros(num_samples, dtype=np.float64)
        self.sum_ht = np.zeros((256, num_samples), dtype=np.float64)
        self.rho = None

    def add_trace(self, trace: np.ndarray, plaintext_byte: int) -> None:
        h = _LEAK_TABLE[:, plaintext_byte]  # (256,) leakage for every key guess, this trace
        self.n += 1
        self.sum_h += h
        self.sum_h2 += h ** 2
        self.sum_t += trace
        self.sum_t2 += trace ** 2
        self.sum_ht += np.outer(h, trace)

    def compute_rho(self) -> np.ndarray:
        n = self.n
        eps = 1e-24
        mean_h = self.sum_h / n
        mean_t = self.sum_t / n
        std_h = np.sqrt(np.maximum((self.sum_h2 - n * mean_h ** 2) / (n - 1), 0) + eps)
        std_t = np.sqrt(np.maximum((self.sum_t2 - n * mean_t ** 2) / (n - 1), 0) + eps)
        cov = (self.sum_ht - n * np.outer(mean_h, mean_t)) / (n - 1)
        self.rho = np.clip(cov / (std_h[:, None] * std_t[None, :]), -1.0, 1.0)
        return self.rho

    def best_guess(self):
        """Returns (best_key_byte, confidence, sample_index)."""
        rho = self.compute_rho()
        peak_per_guess = np.max(np.abs(rho), axis=1)
        best = int(np.argmax(peak_per_guess))
        sample_index = int(np.argmax(np.abs(rho[best])))
        return best, float(peak_per_guess[best]), sample_index


class AESKeyCPA:
    """16 AESByteCPA attackers running in parallel, one per key byte position."""

    def __init__(self, num_samples: int):
        self.attackers = [AESByteCPA(num_samples) for _ in range(16)]
        self.n = 0

    def add_trace(self, trace: np.ndarray, plaintext: bytes) -> None:
        assert len(plaintext) == 16
        for i in range(16):
            self.attackers[i].add_trace(trace, plaintext[i])
        self.n += 1

    def recovered_key(self):
        """Returns (key_bytes, confidences, sample_indices)."""
        guesses, confidences, indices = [], [], []
        for a in self.attackers:
            g, c, s = a.best_guess()
            guesses.append(g)
            confidences.append(c)
            indices.append(s)
        return bytes(guesses), confidences, indices

    def report(self, expected_key: bytes = None) -> None:
        key, conf, idx = self.recovered_key()
        print(f"\n--- after {self.n} traces ---")
        print(f"Recovered key: {key.hex()}")
        print("byte  guess  confidence  sample_idx" + ("  correct?" if expected_key else ""))
        for i in range(16):
            line = f" {i:3d}   0x{key[i]:02x}    {conf[i]:.4f}      {idx[i]}"
            if expected_key is not None:
                line += "        YES" if key[i] == expected_key[i] else "        no"
            print(line)
        if expected_key is not None:
            n_correct = sum(1 for i in range(16) if key[i] == expected_key[i])
            print(f"{n_correct}/16 bytes correct" +
                  (" -- FULL KEY RECOVERED" if n_correct == 16 else ""))

    def plot_confidences(self, out_dir: str, label: str = "aes_cpa") -> str:
        os.makedirs(out_dir, exist_ok=True)
        _, conf, _ = self.recovered_key()
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(range(16), conf)
        ax.set_xlabel("key byte index")
        ax.set_ylabel("best correlation (|rho|)")
        ax.set_title(f"{label}: per-byte confidence after {self.n} traces")
        fig.tight_layout()
        path = os.path.join(out_dir, f"{label}_confidence_{self.n}traces.png")
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return path
