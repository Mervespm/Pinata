"""Collect Falcon power traces with Inspector -> .trs. Flat and simple: load the
keys, then for each one send the key, arm, sign a message, grab the trace, save
it. Records Channel A (power) and triggers on the External input (PC2 rising
edge). Live progress; Ctrl-C stops between traces."""
import json
import os
import sys

import serial
import riscure.inspector
from riscure.inspector import ManualInputTraceSetSink

# --------------------------- config ---------------------------
PORT, BAUD      = "COM6", 115200
KEYSET          = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys", "falcon_f0_forced_21k")
OUT             = "SCA Falcon Pinata Acquisition.trs"
N               = None          # None = one trace per key (whole set); or an int for a quick test
SAMPLE_RATE_MHZ = 1000          # 1 GS/s
NUM_SAMPLES     = 200000        # 200 us window
MEAS_CH, MEAS_RANGE_V = "Channel A", 0.5     # power probe channel + range
TRIG_CH, TRIG_LEVEL_V = "External", 0.5      # PC2 edge into the EXT trigger input
SET_KEY, SIGN   = b"\x9B", b"\x9C"           # firmware command bytes
SIG_SIZE, MSG_SIZE = 666, 16

# --------------------------- load the key set ---------------------------
meta = json.load(open(KEYSET + ".meta.json"))
data = open(KEYSET + ".bin", "rb").read()
rs, nkeys, fields = meta["record_size"], meta["num_keys"], meta["fields"]

def field(i, name):
    s = fields[name]
    off = i * rs + s["offset"]
    return data[off: off + s["size"]]

n = nkeys if N is None else min(N, nkeys)

# --------------------------- connect + capture ---------------------------
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
    print(f"{NUM_SAMPLES} samples @ {SAMPLE_RATE_MHZ} MHz | record {MEAS_CH} | trigger {TRIG_CH} @ {TRIG_LEVEL_V} V")

    source = ins.create_scope_source(scope)
    sink = ManualInputTraceSetSink(ins, source.trace_meta_data,
                                   os.path.join(ins.settings.trace_set_path, OUT)).run()

    written = 0
    print(f"Collecting {n} traces -> {OUT}")
    try:
        for i in range(n):
            pk, sk, f, g = field(i, "pk"), field(i, "sk"), field(i, "f"), field(i, "g")
            f0 = f[0] - 256 if f[0] >= 128 else f[0]        # f[0] as signed int8

            ser.reset_input_buffer()
            ser.write(SET_KEY + pk + sk)
            if ser.read(1) != b"\x00":
                raise RuntimeError(f"set-key failed at key {i}")

            scope.arm()
            ser.write(SIGN + os.urandom(MSG_SIZE))
            if ser.read(1) != b"\x00" or len(ser.read(SIG_SIZE)) != SIG_SIZE:
                raise RuntimeError(f"sign failed at key {i}")

            with source.get() as measurement:
                for trace in measurement.get_traces(MEAS_CH):
                    trace.parameters["f0_class"] = bytes([f0 + 10])   # -10..+10 -> 0..20
                    trace.parameters["F_COEFFS"] = f
                    trace.parameters["G_COEFFS"] = g
                    sink.put(trace)

            written += 1
            if written <= 10 or written % 100 == 0 or written == n:
                print(f"  {written}/{n}   (f0={f0:+d})", flush=True)
    except KeyboardInterrupt:
        print(f"\nCtrl-C: stopping. {written} traces saved to {OUT}.")
    finally:
        ser.close()
    print(f"Done: {written} traces -> {OUT}")
