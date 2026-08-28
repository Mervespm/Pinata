"""Test: does averaging repeated signs of the SAME key improve classification?

f's decode doesn't depend on the message, and this firmware's sign uses a
fixed deterministic seed - so N repeated SIGN calls on one already-loaded
key are, in theory, the same underlying computation measured N times, with
only real analog measurement noise differing between captures. Averaging
those N traces should cancel that noise and raise the effective SNR by
~N, without touching the leakage model or POIs at all.

This picks ONE key from the profiling set (default: the first one whose
f[0] falls in a currently-ambiguous same/near-Hamming-weight bucket),
captures it N times, and compares:
  - classification of each of the N individual (unaveraged) traces
  - classification of the N-trace average ("super-trace")
against the existing pooled templates from falcon_template_attack.py.

Usage:
    python falcon_average_repeat_test.py [COM_PORT] [KEY_SET_PREFIX] [KEY_INDEX] [N_REPEATS]
"""
import ctypes
import json
import os
import sys
from time import sleep

import numpy as np

import falcon_template_attack as fta
from pico_scope_3000a import ps, assert_pico_ok, mV2adc, RANGE_INDEX, A_COUPLING, A_PROBE

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(HERE))

SIGNATURE_SIZE = 666
REQUEST_SET_KEY = b"\x9B"
REQUEST_SIGN = b"\x9C"
MESSAGE = b"TriggerLoopTest!"

WINDOW_MS = 0.15
PRE_TRIG_FRAC = 0.15
A_RANGE_V = 0.5
B_THRESH_V = 0.5


def write_chunked(ser, data, chunk_size=64, gap_s=0.005):
    for i in range(0, len(data), chunk_size):
        ser.write(data[i:i + chunk_size])
        ser.flush()
        sleep(gap_s)


def load_keyset(prefix):
    with open(prefix + ".meta.json") as f:
        meta = json.load(f)
    record_size, num_keys, fields = meta["record_size"], meta["num_keys"], meta["fields"]
    with open(prefix + ".bin", "rb") as f:
        data = f.read()
    keys = []
    for i in range(num_keys):
        base = i * record_size
        def field(name, base=base):
            spec = fields[name]
            return data[base + spec["offset"]: base + spec["offset"] + spec["size"]]
        keys.append({"pk": field("pk"), "sk": field("sk"), "f": field("f")})
    return keys


def open_scope():
    handle = ctypes.c_int16()
    assert_pico_ok(ps.ps3000aOpenUnit(ctypes.byref(handle), None))
    maxadc = ctypes.c_int16()
    assert_pico_ok(ps.ps3000aMaximumValue(handle, ctypes.byref(maxadc)))
    chA = ps.PS3000A_CHANNEL["PS3000A_CHANNEL_A"]
    chB = ps.PS3000A_CHANNEL["PS3000A_CHANNEL_B"]
    chExt = ps.PS3000A_CHANNEL["PS3000A_EXTERNAL"]
    none_mode = ps.PS3000A_RATIO_MODE["PS3000A_RATIO_MODE_NONE"]

    assert_pico_ok(ps.ps3000aSetChannel(handle, chA, 1, ps.PS3000A_COUPLING["PS3000A_" + A_COUPLING], RANGE_INDEX[A_RANGE_V], 0.0))
    assert_pico_ok(ps.ps3000aSetChannel(handle, chB, 0, ps.PS3000A_COUPLING["PS3000A_DC"], RANGE_INDEX[1.0], 0.0))
    thr = mV2adc(B_THRESH_V * 1000.0, RANGE_INDEX[5.0], maxadc)
    rising = ps.PS3000A_THRESHOLD_DIRECTION["PS3000A_RISING"]
    assert_pico_ok(ps.ps3000aSetSimpleTrigger(handle, 1, chExt, thr, rising, 0, 0))

    interval_ns = ctypes.c_float(0)
    max_samples = ctypes.c_int32(0)
    timebase = 0
    while True:
        status = ps.ps3000aGetTimebase2(handle, timebase, 2, ctypes.byref(interval_ns), 0, ctypes.byref(max_samples), 0)
        if status == 0:
            break
        timebase += 1
    fs = 1e9 / interval_ns.value
    n_samples = int(WINDOW_MS / 1000.0 * fs)
    n_pre = int(n_samples * PRE_TRIG_FRAC)
    n_post = n_samples - n_pre
    bufA = (ctypes.c_int16 * n_samples)()
    assert_pico_ok(ps.ps3000aSetDataBuffer(handle, chA, ctypes.byref(bufA), n_samples, 0, none_mode))
    return {"handle": handle, "maxadc": maxadc, "none_mode": none_mode, "timebase": timebase,
            "fs": fs, "n_samples": n_samples, "n_pre": n_pre, "n_post": n_post, "bufA": bufA}


def capture_one(ser, scope):
    assert_pico_ok(ps.ps3000aRunBlock(scope["handle"], scope["n_pre"], scope["n_post"],
                                      scope["timebase"], 0, None, 0, None, None))
    sleep(0.05)
    ser.write(REQUEST_SIGN + MESSAGE)
    status = ser.read(1)
    if len(status) != 1 or status[0] != 0:
        ps.ps3000aStop(scope["handle"])
        return None
    ser.read(SIGNATURE_SIZE)

    ready = ctypes.c_int16(0)
    waited = 0.0
    assert_pico_ok(ps.ps3000aIsReady(scope["handle"], ctypes.byref(ready)))
    while ready.value == 0:
        sleep(0.001)
        waited += 0.001
        if waited > 5.0:
            ps.ps3000aStop(scope["handle"])
            return None
        assert_pico_ok(ps.ps3000aIsReady(scope["handle"], ctypes.byref(ready)))
    n = ctypes.c_uint32(scope["n_samples"])
    overflow = ctypes.c_int16(0)
    assert_pico_ok(ps.ps3000aGetValues(scope["handle"], 0, ctypes.byref(n), 1, scope["none_mode"], 0, ctypes.byref(overflow)))
    power = np.array(scope["bufA"], dtype=np.float64)
    return power / scope["maxadc"].value * A_RANGE_V * A_PROBE * 1e3


def main():
    import serial

    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    prefix = sys.argv[2] if len(sys.argv) > 2 else os.path.join(PROJECT_ROOT, "falcon_profile_keys")
    key_index = int(sys.argv[3]) if len(sys.argv) > 3 else None
    n_repeats = int(sys.argv[4]) if len(sys.argv) > 4 else 20

    keys = load_keyset(prefix)
    if key_index is None:
        # Default: pick a key whose f[0] sits in a currently-ambiguous
        # same/near-Hamming-weight bucket (e.g. 4, which collides with 1/2
        # on HW32=1 and sits right next to the 5/6 HW32=2 boundary).
        for i, k in enumerate(keys):
            f0 = np.frombuffer(k["f"][:1], dtype=np.int8)[0]
            if f0 == 4:
                key_index = i
                break
        if key_index is None:
            key_index = 0
    key = keys[key_index]
    f0_true = int(np.frombuffer(key["f"][:1], dtype=np.int8)[0])
    print(f"Using key #{key_index}, true f[0] = {f0_true} (HW32={fta.hw32(f0_true)})")

    templates_path = os.path.join(HERE, "falcon_captures", "f_only_profile_falcon_profile_keys", "templates_all.npz")
    tpl = np.load(templates_path)
    pois, cov = tpl["pois"], tpl["cov"]
    classes = tpl["classes"]
    means = {int(c): m for c, m in zip(classes, tpl["means"])}
    print(f"Loaded templates: {len(classes)} classes, POIs={list(pois)}")

    ser = serial.Serial(port, 115200, timeout=5.0)
    sleep(0.3)
    ser.reset_input_buffer()
    scope = open_scope()

    print(f"\nSetting key on board ... ", end="")
    write_chunked(ser, REQUEST_SET_KEY + key["pk"] + key["sk"])
    status = ser.read(1)
    if len(status) != 1 or status[0] != 0:
        raise SystemExit(f"SET_KEY FAILED (status={status!r})")
    print("OK")

    print(f"Capturing {n_repeats} repeated signs of this SAME key ...")
    traces = []
    for i in range(n_repeats):
        t = capture_one(ser, scope)
        if t is None:
            print(f"  [{i}] capture failed, skipping")
            continue
        traces.append(t)
        print(f"  [{i}] OK")
    ps.ps3000aStop(scope["handle"])
    ps.ps3000aCloseUnit(scope["handle"])
    ser.close()

    traces = np.array(traces)
    print(f"\nGot {len(traces)}/{n_repeats} usable traces.")

    def classify_and_report(x, label):
        vals = x[pois]
        from scipy.stats import multivariate_normal
        lls = {c: multivariate_normal.logpdf(vals, mean=mu, cov=cov) for c, mu in means.items()}
        ranked = sorted(lls, key=lls.get, reverse=True)
        rank = ranked.index(f0_true) + 1 if f0_true in lls else None
        top3 = ranked[:3]
        print(f"{label}: predicted={ranked[0]}  true={f0_true}  "
              f"true's rank={rank}/{len(classes)}  top3={top3}")
        return rank

    print(f"\n--- Individual (unaveraged) traces, true f[0]={f0_true} ---")
    single_ranks = [classify_and_report(t, f"trace {i}") for i, t in enumerate(traces)]

    avg_trace = traces.mean(axis=0)
    print(f"\n--- {len(traces)}-trace average ---")
    avg_rank = classify_and_report(avg_trace, "averaged")

    print(f"\nSummary: mean rank of true class across {len(traces)} single traces = "
          f"{np.mean([r for r in single_ranks if r]):.2f}/{len(classes)}")
    print(f"         rank of true class on the averaged super-trace = {avg_rank}/{len(classes)}")


if __name__ == "__main__":
    main()
