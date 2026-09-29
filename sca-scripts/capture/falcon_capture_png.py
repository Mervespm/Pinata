"""
Capture a Falcon (FN-DSA-512) signing trace on Pinata with the PicoScope 3000
(Python, no Inspector) and save it as CSV + PNG so you can see where things are.

Workflow: run it a few times with different WINDOW_MS to zoom -
  - large  WINDOW_MS  -> the FULL signing operation
  - medium WINDOW_MS  -> the whole f decode
  - small  WINDOW_MS  -> just f[0]
Each run writes <OUT>.csv and <OUT>.png. The PNG is a plain trace to eyeball
where the regions are; add the styling afterwards.

Uses pico_scope_3000a.py (next to this file). One fixed key is signed N_TRACES
times; the mean (clean) and one raw signature are both saved.

Requires: pico_scope_3000a.py, pyserial, matplotlib, and falcon firmware flashed.
"""
import json
import os
import sys

import numpy as np
import serial
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pico_scope_3000a import Scope   # PicoScope 3000 wrapper you already have

# ============================== CONFIG ==============================
PORT          = "COM6"
BAUD          = 115200
KEYSET_PREFIX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "keys", "falcon_f0_forced_21k")
KEY_INDEX     = 0            # which key (its f[0] is the fixed secret in the trace)
N_TRACES      = 5           # repeats to average for a clean trace
ZOOM   = "decode1"           
OUT       = f"falcon_trace_{ZOOM}"   # writes OUT.csv and OUT.png
# ====================================================================

SET_KEY = b"\x9B"; SIGN = b"\x9C"
PK_SIZE, SK_SIZE, SIG_SIZE, MSG_SIZE = 897, 1281, 666, 16


def load_key(prefix, idx):
    with open(prefix + ".meta.json") as fh:
        meta = json.load(fh)
    rs, fields = meta["record_size"], meta["fields"]
    data = open(prefix + ".bin", "rb").read()
    base = idx * rs

    def field(name):
        s = fields[name]
        return data[base + s["offset"]: base + s["offset"] + s["size"]]

    return field("pk"), field("sk"), np.frombuffer(field("f"), np.int8).copy()


def set_key(ser, pk, sk):
    ser.reset_input_buffer()
    ser.write(SET_KEY + pk + sk)
    if ser.read(1) != b"\x00":
        raise RuntimeError("set-key not acked")


def sign_once(ser):
    ser.reset_input_buffer()
    ser.write(SIGN + os.urandom(MSG_SIZE)); ser.flush()
    if ser.read(1) != b"\x00":
        raise RuntimeError("sign failed")
    if len(ser.read(SIG_SIZE)) != SIG_SIZE:
        raise RuntimeError("short signature")


def main():
    pk, sk, f = load_key(KEYSET_PREFIX, KEY_INDEX)
    f0 = int(f[0])
    print(f"Key {KEY_INDEX}: f[0] = {f0:+d}")

    print(f"Opening {PORT} + PicoScope ...")
    ser = serial.Serial(PORT, BAUD, timeout=5.0)
    set_key(ser, pk, sk)
    scope = Scope()                      # uses the settings in pico_scope_3000a.py
    fs = scope.fs; n = scope.n_samples
    print(f"  {n} samples @ {fs/1e6:.1f} MS/s")

    acc = None; raw0 = None
    try:
        for i in range(N_TRACES):
            scope.arm()
            sign_once(ser)
            power, _ = scope.read()
            power = np.asarray(power, dtype=np.float64)
            acc = power if acc is None else acc + power
            if raw0 is None:
                raw0 = power.copy()
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{N_TRACES}")
        mean = acc / N_TRACES
    finally:
        scope.close(); ser.close()

    t_us = np.arange(n) / fs * 1e6
    # ---- MATLAB .mat file (native; fast + compact for big traces) ----
    # In MATLAB:  S = load('falcon_trace_full.mat');  plot(S.time_us, S.power_raw)
    from scipy.io import savemat
    savemat(OUT + ".mat", {
        "time_us":    t_us.astype(np.float64),
        "power_mean": mean.astype(np.float64),   # averaged (clean) - use for f-decode / f[0] zoom
        "power_raw":  raw0.astype(np.float64),   # one signature - use for the full overview
        "fs_hz":      float(fs),
        "f0":         int(f0),
        "n_samples":  int(n),
    })
    # PNG (plain, for eyeballing the regions)
    fig, ax = plt.subplots(figsize=(14, 4))
    ax.plot(t_us, raw0, color="tab:blue", lw=0.5)
    ax.set_xlabel("time (us)"); ax.set_ylabel("power (ADC)")
    ax.set_title(f"Falcon signing  |  f[0] = {f0:+d}  |  {n} samples @ {fs/1e6:.1f} MS/s "
                 f"({n/fs*1e3:.2f} ms window)")
    ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(OUT + ".png", dpi=140)
    print(f"\nSaved {OUT}.mat and {OUT}.png  ({n} samples). "
          f"Load in MATLAB: S = load('{OUT}.mat'); plot(S.time_us, S.power_raw)")


if __name__ == "__main__":
    main()
