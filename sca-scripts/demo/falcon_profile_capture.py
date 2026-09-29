"""Step 1 - PROFILING capture (Inspector).

Signs MANY known keys on THIS firmware and labels every trace with its true
f[0], to build the training set the template is fit on. Uses the exact same
scope config as the demo capture (Channel A 0.2 V, 200k @ 1000 MHz, decode
trigger) so the profile and the demo live in the SAME measurement domain -
that is the whole point: a profiled template only transfers within one setup.

Output -> C:/Users/mervkara/Inspector/data/demo/demo_profile.trs
Then:    python falcon_train.py
"""
import json
import os

import numpy as np
import serial
import riscure.inspector
from riscure.inspector import ManualInputTraceSetSink

PORT, BAUD = "COM6", 115200
KEYSET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "keys", "falcon_f0_forced_21k")
KEYS_PER_CLASS = 1000                # x 21 classes; 1000 = full 21000-trace profile (lower for a quicker run)
OUT = "C:/Users/mervkara/Inspector/data/demo/demo_profile.trs"

SET_KEY, SIGN = bytes([0x9B]), bytes([0x9C])
SIG_SIZE, MSG_SIZE = 666, 16
SAMPLE_RATE_MHZ, NUM_SAMPLES = 1000, 10000
MEAS_CH, MEAS_RANGE_V = "Channel A", 0.2      # 0.2 V -> ~+-60 counts, matches the demo capture
TRIG_CH, TRIG_LEVEL_V = "External", 0.5

# ---- load a balanced set of known keys (f[0] = -10..+10) ----
meta = json.load(open(KEYSET + ".meta.json"))
data = open(KEYSET + ".bin", "rb").read()
rs, F = meta["record_size"], meta["fields"]


def field(i, name):
    o = i * rs + F[name]["offset"]
    return data[o:o + F[name]["size"]]


by_class = {}
for i in range(meta["num_keys"]):
    f0 = int(np.frombuffer(field(i, "f")[:1], np.int8)[0])
    by_class.setdefault(f0, []).append(i)

rng = np.random.default_rng(0)
sel = []
for c in sorted(by_class):
    idx = by_class[c][:]
    rng.shuffle(idx)
    sel += [(i, c) for i in idx[:KEYS_PER_CLASS]]
rng.shuffle(sel)
print(f"profiling {len(sel)} keys ({KEYS_PER_CLASS}/class x {len(by_class)} classes)")

ser = serial.Serial(PORT, BAUD, timeout=5.0)
with riscure.inspector.connect() as ins:
    print("Inspector connected")
    scopes = list(ins.get_connected_oscilloscopes())
    pico = next((s for s in scopes if "3000" in s["name"]), scopes[0])
    scope = ins.open_scope_device(pico)
    scope.scope_settings.number_of_samples = NUM_SAMPLES
    scope.scope_settings.time_per_sample = 1 / (SAMPLE_RATE_MHZ * 1_000_000)
    scope.channel_settings[MEAS_CH].enabled = True
    scope.channel_settings[MEAS_CH].range = MEAS_RANGE_V
    scope.trigger_settings.trigger_channel_name = TRIG_CH
    scope.trigger_settings.trigger_level = TRIG_LEVEL_V
    scope.calibrate()
    print(f"{NUM_SAMPLES} samples @ {SAMPLE_RATE_MHZ} MHz | {MEAS_CH} {MEAS_RANGE_V} V | "
          f"trigger {TRIG_CH} @ {TRIG_LEVEL_V} V")

    source = ins.create_scope_source(scope)
    sink = ManualInputTraceSetSink(ins, source.trace_meta_data,
                                   os.path.join(ins.settings.trace_set_path, OUT)).run()
    print(f"Collecting -> {OUT}")
    for n, (i, f0) in enumerate(sel):
        ser.reset_input_buffer()
        ser.write(SET_KEY + field(i, "pk") + field(i, "sk"))     # load this key
        if ser.read(1) != bytes([0]):
            raise RuntimeError(f"set-key not acked (key {i})")
        scope.arm()                                              # arm, then sign (decode leaks here)
        ser.write(SIGN + os.urandom(MSG_SIZE))
        if ser.read(1) != bytes([0]) or len(ser.read(SIG_SIZE)) != SIG_SIZE:
            raise RuntimeError(f"sign failed (key {i})")
        with source.get() as m:
            for tr in m.get_traces(MEAS_CH):
                tr.parameters["f0_class"] = bytes([f0 + 10])     # label = true f[0] + 10 (0..20)
                tr.parameters["f0"] = bytes([f0 & 0xFF])         # true f[0], signed int8
                tr.parameters["f"] = field(i, "f")               # secret polynomial f (512 x int8)
                tr.parameters["sk"] = field(i, "sk")             # full encoded secret key
                sink.put(tr)
        if (n + 1) % 50 == 0:
            print(f"  {n + 1}/{len(sel)}", flush=True)
    ser.close()
print("done ->", OUT)
print("next:  python falcon_train.py")
