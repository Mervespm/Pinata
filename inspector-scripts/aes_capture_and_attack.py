"""Acquisition + live incremental CPA against the Pinata board's software
AES-128 (CMD_SWAES128_ENC 0xAE / CMD_AES128_KEYCHANGE 0xE7 - see main.h).

Combines this project's already-validated Pinata serial + PicoScope 3000a
pipeline (pico_scope_3000a.py: chunked writes, retry-on-short-read, Channel
B trigger already wired and confirmed clean) with the AES CPA engine in
aes_cpa.py (adapted from SCA_methods.py's CPAonAESonPlaintext, generalized
to all 16 key bytes, made incremental like CPACalc.py).

Requires hw.dfu flashed (the classic-crypto build - falcon.dfu does not
understand 0xAE/0xE7 at all).

Usage: python aes_capture_and_attack.py [COM_PORT] [NUM_TRACES]
"""
import sys
from datetime import datetime
from time import sleep

import numpy as np
import serial

from pico_scope_3000a import Scope
from aes_cpa import AESKeyCPA

PLAINTEXT_SIZE = 16
CIPHERTEXT_SIZE = 16
REQUEST_AES_ENC = b"\xAE"
REQUEST_AES_SETKEY = b"\xE7"

# Same default key already baked into this firmware (main.c's defaultKeyAES) -
# setting it explicitly just makes the ground truth for verification obvious.
KNOWN_KEY = bytes.fromhex("cafebabedeadbeef0001020304050607")

WINDOW_MS = 2.0          # cast a wide net first - narrow down once we see where AES's activity actually is
REPORT_EVERY = 100       # print/plot progress every N traces


def write_chunked(ser, data, chunk_size=64, gap_s=0.005):
    for i in range(0, len(data), chunk_size):
        ser.write(data[i:i + chunk_size])
        ser.flush()
        sleep(gap_s)


def do_request_retrying(ser, request_prefix, payload, response_size, retries=5):
    for attempt in range(retries):
        ser.write(request_prefix + payload)
        result = ser.read(response_size)
        if len(result) == response_size:
            return result
        print(f"  [warning] short/empty response ({len(result)} bytes), retrying ({attempt + 1}/{retries})")
        ser.reset_input_buffer()
        sleep(0.05)
    raise RuntimeError(f"no valid {response_size}-byte response after {retries} attempts")


def open_target(port):
    """Open the serial link and set the known key. Raises if the key echo
    doesn't match (caller decides whether that's fatal or worth retrying)."""
    ser = serial.Serial(port, 115200, timeout=2.0)
    sleep(0.3)
    ser.reset_input_buffer()
    write_chunked(ser, REQUEST_AES_SETKEY + KNOWN_KEY)
    echoed = ser.read(16)
    if echoed != KNOWN_KEY:
        ser.close()
        raise RuntimeError(f"key echo mismatch (got {echoed.hex() if echoed else '<empty>'})")
    return ser


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    num_traces = int(sys.argv[2]) if len(sys.argv) > 2 else 2000

    out_dir = "aes_cpa_results_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    print(f"Opening serial port {port} and setting AES key ... ", end="")
    ser = open_target(port)
    print("OK")

    print("Opening PicoScope 3000a ... ")
    scope = Scope(window_ms=WINDOW_MS, pre_trig_frac=0.0, trigger_source="EXTERNAL")
    print("OK\n")

    cpa = AESKeyCPA(num_samples=scope.n_samples)

    # The serial/scope link has been observed to go fully dead mid-run in a
    # way that isn't tied to any specific code path (near-identical runs
    # have gone 20/20 clean, then failed on trace 1 - looks like transient
    # hardware/environment flakiness on this bench, not a deterministic
    # bug). Rather than crash the whole acquisition on one bad trace, do a
    # full reconnect (close+reopen both scope and serial, re-send the key)
    # and retry that trace, up to MAX_HARD_RECOVERIES times before finally
    # giving up.
    MAX_HARD_RECOVERIES = 30
    hard_recoveries = 0

    print(f"Collecting {num_traces} traces (Ctrl+C to stop early and see current results) ...\n")
    i = 0
    try:
        while i < num_traces:
            plaintext = bytes(np.random.randint(0, 256, size=16, dtype=np.uint8))
            try:
                scope.arm()
                sleep(0.02)  # avoid overlapping the RunBlock USB transaction with the next serial write
                ciphertext = do_request_retrying(ser, REQUEST_AES_ENC, plaintext, CIPHERTEXT_SIZE)
                power, _trig = scope.read()
            except (RuntimeError, TimeoutError) as exc:
                hard_recoveries += 1
                if hard_recoveries > MAX_HARD_RECOVERIES:
                    print(f"\n[fatal] {MAX_HARD_RECOVERIES} hard recoveries exhausted, giving up "
                          f"at trace {i}/{num_traces}: {exc}")
                    raise
                print(f"\n[recovery {hard_recoveries}/{MAX_HARD_RECOVERIES}] link dead ({exc}) - "
                      f"closing/reopening scope + serial and retrying trace {i} ...")
                try:
                    scope.close()
                except Exception:
                    pass
                try:
                    ser.close()
                except Exception:
                    pass
                sleep(2.0)  # let USB settle before reopening either device
                ser = open_target(port)
                scope = Scope(window_ms=WINDOW_MS, pre_trig_frac=0.0, trigger_source="EXTERNAL", verbose=False)
                print("  reconnected, resuming\n")
                continue

            cpa.add_trace(power, plaintext)
            i += 1

            if i % REPORT_EVERY == 0 or i == num_traces:
                cpa.report(expected_key=KNOWN_KEY)
                png = cpa.plot_confidences(out_dir)
                print(f"  saved -> {png}")
    except KeyboardInterrupt:
        print("\nStopped early by user.")
    finally:
        scope.close()
        ser.close()

    print(f"\n=== Final result ({hard_recoveries} hard recoveries needed) ===")
    cpa.report(expected_key=KNOWN_KEY)


if __name__ == "__main__":
    main()
