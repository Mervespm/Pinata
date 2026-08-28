"""Batch capture of Falcon's 'f' secret-key coefficient decode ONLY, at the
scope's max single-channel rate, across many independent valid keys.

Why vary the key (not the message): f's decode happens purely from the
secret key bytes, before the message is ever touched - the trace is
essentially message-independent. What we actually want to vary across
traces, for real leakage analysis, is f itself - hence one independent
valid key per trace (via host_keygen; see BUILDING_ON_WINDOWS.md for why a
single-coefficient "sweep" of one base key doesn't work - only one key
sample is signable that way, since G gets recomputed fresh from f/g/F on
every sign() and almost never stays small unless f is barely perturbed).

Trigger: EXTERNAL input (not channel B) - bracket only around the decode of
'f' (main.c's narrow-trigger patch), physically wired to the scope's EXT
trigger BNC. Freeing channel B from double duty as a digitized channel gets
this scope to its single-channel max rate (1 GS/s on this unit, vs 500 MS/s
with 2 channels active).

Requires a key set from host_keygen, e.g.:
    Pinata/tools/host_keygen/build/host_keygen.exe 20 falcon_f_batch_keys
(run from the project root - writes falcon_f_batch_keys.bin/.meta.json)

Usage: python falcon_capture_f_only_batch.py [COM_PORT] [KEY_SET_PREFIX]
"""
import ctypes
import json
import os
import sys
from time import sleep

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import serial

from pico_scope_3000a import ps, assert_pico_ok, mV2adc, RANGE_INDEX, A_COUPLING, A_PROBE

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(HERE))

SIGNATURE_SIZE = 666
REQUEST_SET_KEY = b"\x9B"
REQUEST_SIGN = b"\x9C"
MESSAGE = b"TriggerLoopTest!"  # irrelevant to f's decode, kept fixed

WINDOW_MS = 0.15       # tight around f's ~76us pulse (at 168MHz core clock), with margin
PRE_TRIG_FRAC = 0.15
# Overridden locally (not from pico_scope_3000a's shared A_RANGE_V) so this
# doesn't affect the AES scripts that already work at a different range.
A_RANGE_V = 0.5
B_THRESH_V = 0.5        # EXTERNAL trigger threshold (see picoscopeMethods.py's fixed 5V front end)
DELAY_S = 0.0


def write_chunked(ser, data, chunk_size=64, gap_s=0.005):
    """Large single writes (e.g. the ~2.2KB SET_KEY payload) have been
    observed to arrive at the board incomplete, wedging its get_bytes()
    mid-command. Chunking with small flushes makes that much less likely."""
    for i in range(0, len(data), chunk_size):
        ser.write(data[i:i + chunk_size])
        ser.flush()
        sleep(gap_s)


def load_keyset(prefix):
    with open(prefix + ".meta.json") as f:
        meta = json.load(f)
    record_size = meta["record_size"]
    num_keys = meta["num_keys"]
    fields = meta["fields"]
    with open(prefix + ".bin", "rb") as f:
        data = f.read()
    keys = []
    for i in range(num_keys):
        base = i * record_size
        def field(name):
            spec = fields[name]
            return data[base + spec["offset"]: base + spec["offset"] + spec["size"]]
        keys.append({"pk": field("pk"), "sk": field("sk"), "f": field("f"), "g": field("g")})
    return keys


def open_serial(port):
    ser = serial.Serial(port, 115200, timeout=5.0)
    sleep(0.3)
    ser.reset_input_buffer()
    return ser


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

    ext_range = RANGE_INDEX[5.0]
    thr = mV2adc(B_THRESH_V * 1000.0, ext_range, maxadc)
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
        if timebase > 50:
            raise RuntimeError("no valid fast timebase found")
    fs = 1e9 / interval_ns.value

    n_samples = int(WINDOW_MS / 1000.0 * fs)
    n_pre = int(n_samples * PRE_TRIG_FRAC)
    n_post = n_samples - n_pre

    bufA = (ctypes.c_int16 * n_samples)()
    assert_pico_ok(ps.ps3000aSetDataBuffer(handle, chA, ctypes.byref(bufA), n_samples, 0, none_mode))

    return {
        "handle": handle, "maxadc": maxadc, "none_mode": none_mode,
        "timebase": timebase, "fs": fs, "n_samples": n_samples,
        "n_pre": n_pre, "n_post": n_post, "bufA": bufA,
    }


def close_scope(scope):
    try:
        ps.ps3000aStop(scope["handle"])
    except Exception:
        pass
    try:
        ps.ps3000aCloseUnit(scope["handle"])
    except Exception:
        pass


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    prefix = sys.argv[2] if len(sys.argv) > 2 else os.path.join(PROJECT_ROOT, "falcon_f_batch_keys")

    keys = load_keyset(prefix)
    print(f"Loaded {len(keys)} keys from {prefix}.bin/.meta.json")

    # Fixed (not timestamped) output dir, keyed to the key set itself, so a
    # rerun after a disconnect naturally continues in the same place instead
    # of starting a fresh empty folder - nothing already captured is ever
    # discarded or redone.
    keyset_name = os.path.basename(prefix)
    out_dir = os.path.join(HERE, "falcon_captures", f"f_only_profile_{keyset_name}")
    os.makedirs(out_dir, exist_ok=True)
    print(f"Output folder: {out_dir}")

    already_done = {
        i for i in range(len(keys))
        if os.path.exists(os.path.join(out_dir, f"trace_{i:03d}.npy"))
    }
    if already_done:
        print(f"Resuming: {len(already_done)}/{len(keys)} traces already captured in a previous run, skipping those.")

    ser = open_serial(port)
    scope = open_scope()
    original_fs = scope["fs"]
    np.save(os.path.join(out_dir, "time_us.npy"),
            (np.arange(scope["n_samples"]) - scope["n_pre"]) / scope["fs"] * 1e6)
    print(f"Rate: {scope['fs']/1e6:.3f} MS/s (timebase {scope['timebase']}), "
          f"{scope['n_samples']} samples for {WINDOW_MS} ms window (pre-trig {scope['n_pre']})\n")

    MAX_HARD_RECOVERIES = 20
    hard_recoveries = 0
    ok_count = len(already_done)

    # A genuinely wedged board doesn't raise an exception - ser.read()
    # just silently times out and returns b'', which the checks below
    # treat as an ordinary "skip this key" outcome. Left alone, that means
    # a wedge just burns through every remaining key doing nothing until a
    # human notices. Track consecutive skips and force the same hard-
    # recovery reconnect path a raised exception would trigger.
    MAX_CONSECUTIVE_SKIPS = 3
    consecutive_skips = 0

    try:
        for i, key in enumerate(keys):
            if i in already_done:
                continue

            try:
                # Defensive: discard any stale byte left over from a prior
                # iteration before trusting this iteration's status check
                # (a leftover byte could otherwise be misread as a false
                # "success").
                ser.reset_input_buffer()
                write_chunked(ser, REQUEST_SET_KEY + key["pk"] + key["sk"])
                status = ser.read(1)
                if len(status) != 1 or status[0] != 0:
                    consecutive_skips += 1
                    print(f"[{i}] SET_KEY FAILED (status={status!r}) - skipping "
                          f"({consecutive_skips}/{MAX_CONSECUTIVE_SKIPS} consecutive)")
                    if consecutive_skips >= MAX_CONSECUTIVE_SKIPS:
                        raise RuntimeError(f"{consecutive_skips} consecutive silent failures - board is likely wedged")
                    continue

                assert_pico_ok(ps.ps3000aRunBlock(scope["handle"], scope["n_pre"], scope["n_post"],
                                                  scope["timebase"], 0, None, 0, None, None))
                sleep(0.05)
                ser.write(REQUEST_SIGN + MESSAGE)
                status = ser.read(1)
                if len(status) != 1 or status[0] != 0:
                    consecutive_skips += 1
                    print(f"[{i}] sign FAILED (status={status!r}) - skipping "
                          f"({consecutive_skips}/{MAX_CONSECUTIVE_SKIPS} consecutive)")
                    ps.ps3000aStop(scope["handle"])
                    if consecutive_skips >= MAX_CONSECUTIVE_SKIPS:
                        raise RuntimeError(f"{consecutive_skips} consecutive silent failures - board is likely wedged")
                    continue
                ser.read(SIGNATURE_SIZE)

                ready = ctypes.c_int16(0)
                waited = 0.0
                assert_pico_ok(ps.ps3000aIsReady(scope["handle"], ctypes.byref(ready)))
                while ready.value == 0:
                    sleep(0.001)
                    waited += 0.001
                    if waited > 5.0:
                        consecutive_skips += 1
                        print(f"[{i}] trigger never fired - skipping "
                              f"({consecutive_skips}/{MAX_CONSECUTIVE_SKIPS} consecutive)")
                        # Every RunBlock() must be matched by either a
                        # successful GetValues() or an explicit Stop() -
                        # otherwise the NEXT RunBlock() arms on top of a
                        # capture that was never terminated, which is
                        # exactly the kind of thing that makes the scope
                        # misbehave over a long run.
                        ps.ps3000aStop(scope["handle"])
                        if consecutive_skips >= MAX_CONSECUTIVE_SKIPS:
                            raise RuntimeError(f"{consecutive_skips} consecutive silent failures - board is likely wedged")
                        break
                    assert_pico_ok(ps.ps3000aIsReady(scope["handle"], ctypes.byref(ready)))
                else:
                    n = ctypes.c_uint32(scope["n_samples"])
                    overflow = ctypes.c_int16(0)
                    assert_pico_ok(ps.ps3000aGetValues(scope["handle"], 0, ctypes.byref(n), 1,
                                                       scope["none_mode"], 0, ctypes.byref(overflow)))
                    power = np.array(scope["bufA"], dtype=np.float64)
                    power_mV = power / scope["maxadc"].value * A_RANGE_V * A_PROBE * 1e3

                    np.save(os.path.join(out_dir, f"trace_{i:03d}.npy"), power_mV)
                    np.save(os.path.join(out_dir, f"f_true_{i:03d}.npy"), np.frombuffer(key["f"], dtype=np.int8))
                    ok_count += 1
                    consecutive_skips = 0
                    print(f"[{i}] OK ({ok_count}/{len(keys)} total) - f[0]={np.frombuffer(key['f'][:1], dtype=np.int8)[0]}")

                sleep(DELAY_S)

            except (RuntimeError, serial.SerialException, OSError) as exc:
                hard_recoveries += 1
                if hard_recoveries > MAX_HARD_RECOVERIES:
                    print(f"\n[fatal] {MAX_HARD_RECOVERIES} hard recoveries exhausted at key {i}: {exc}")
                    print(f"{ok_count}/{len(keys)} traces are safely saved in {out_dir}.")
                    print(f"Fix the connection and rerun the same command to resume from key {i}.")
                    return
                print(f"\n[recovery {hard_recoveries}/{MAX_HARD_RECOVERIES}] link problem at key {i} ({exc}) - "
                      f"closing/reopening scope + serial, then continuing with the next key "
                      f"(key {i} will be picked up on a rerun) ...")
                try:
                    ser.close()
                except Exception:
                    pass
                close_scope(scope)
                sleep(2.0)
                try:
                    ser = open_serial(port)
                    scope = open_scope()
                    consecutive_skips = 0
                    print("  reconnected, resuming\n")
                except Exception as reopen_exc:
                    print(f"  reconnect failed ({reopen_exc}), will retry on next iteration\n")
                    sleep(3.0)
                    continue

                # The timebase search is deterministic given the same
                # config/hardware, so this should always match the rate
                # every other trace in this file was captured at - but if it
                # ever didn't, later traces would silently misalign against
                # the time_us.npy saved at the start. This is NOT retryable
                # (retrying open_scope() would just pick the same rate
                # again) - fail loudly and stop instead of corrupting the
                # data set with a mismatched time axis.
                if abs(scope["fs"] - original_fs) > 1.0:
                    print(f"\n[fatal] sampling rate changed after reconnect "
                          f"({scope['fs']} vs original {original_fs} Hz) - refusing to "
                          f"continue, this would misalign later traces against the saved "
                          f"time axis.")
                    print(f"{ok_count}/{len(keys)} traces already saved in {out_dir} are fine "
                          f"(all captured at the original rate).")
                    return
                # This key is left uncaptured for the rest of THIS run (the
                # loop moves on to the next one) - it'll be picked up
                # automatically by the resume/skip logic on a future rerun,
                # since it never got a trace_XXX.npy written.
                continue
    finally:
        close_scope(scope)
        try:
            ser.close()
        except Exception:
            pass

    print(f"\n{ok_count}/{len(keys)} traces captured OK.")
    print(f"Saved under {out_dir}")

    # Quick sanity plot of the first successful trace.
    first = None
    for i in range(len(keys)):
        p = os.path.join(out_dir, f"trace_{i:03d}.npy")
        if os.path.exists(p):
            first = i
            break
    if first is not None:
        power_mV = np.load(os.path.join(out_dir, f"trace_{first:03d}.npy"))
        t_us = np.load(os.path.join(out_dir, "time_us.npy"))
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(t_us, power_mV, lw=0.6)
        ax.set_xlabel("time (us)")
        ax.set_ylabel("chan A power (mV)")
        ax.set_title(f"f-only batch sample (trace {first:03d})")
        fig.tight_layout()
        png_path = os.path.join(out_dir, "sample_trace.png")
        fig.savefig(png_path, dpi=120)
        print(f"Saved sanity-check plot -> {png_path}")


if __name__ == "__main__":
    main()
