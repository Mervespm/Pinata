"""10-case capture for the Pinata Falcon (FN-DSA) target, same experiment
shape as HMAC_SCA/SCA_scripts/seed_msg_capture.py, just with the PicoScope
3000a wrapper (pico_scope_3000a.py) and the Pinata UART protocol instead of
the CW310/ps6000a rig.

Cases:
  1-5 : SAME message, signed 5 times
        -> with the firmware's fixed signing seed (Pinata/src/falcon/wrapper.c),
           the signature must be byte-identical every time.
  6-10: DIFFERENT message each run
        -> each signature must independently verify against pk_valid.hex,
           checked via the device's own CMD_SW_FALCON_VERIFY (0x9D), not a
           host recomputation.

Saves one PNG per shot into a timestamped folder under falcon_captures/, plus
messages.hex / signatures.hex (KAT-style plain hex, one line per shot).

Close Riscure Inspector / the PicoScope GUI first - only one program can own
the scope at a time.

Usage: python falcon_capture_10.py [COM_PORT]
"""
import os
import sys
from datetime import datetime
from time import sleep

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import serial

from pico_scope_3000a import Scope, A_RANGE_V, A_PROBE, B_RANGE_V, B_PROBE

MESSAGE_SIZE = 16
PUBLIC_KEY_SIZE = 897
PRIVATE_KEY_SIZE = 1281
SIGNATURE_SIZE = 666

REQUEST_SET_KEY = b"\x9B"
REQUEST_SIGN = b"\x9C"
REQUEST_VERIFY = b"\x9D"

DELAY_S = 1.0
SAME_MSG_RUNS = 5
SAME_MESSAGE = b"TriggerLoopTest!"          # exactly 16 bytes, reused elsewhere in this repo
DIFF_MESSAGES = [                            # cases 6..10, each exactly 16 bytes
    b"Falcon-diff-msg1",
    b"Falcon-diff-msg2",
    b"Falcon-diff-msg3",
    b"Falcon-diff-msg4",
    b"Falcon-diff-msg5",
]
assert len(SAME_MESSAGE) == MESSAGE_SIZE
assert all(len(m) == MESSAGE_SIZE for m in DIFF_MESSAGES)


def build_cases():
    return [SAME_MESSAGE] * SAME_MSG_RUNS + DIFF_MESSAGES


def write_chunked(ser, data, chunk_size=64, gap_s=0.005):
    """Write in small chunks with a flush + tiny gap between each, instead of
    one large burst - large single writes (e.g. the ~2.2KB SET_KEY payload)
    have been observed to arrive at the board incomplete, wedging its
    get_bytes() mid-command until a physical reset."""
    for i in range(0, len(data), chunk_size):
        ser.write(data[i:i + chunk_size])
        ser.flush()
        sleep(gap_s)


def load_valid_key():
    with open("pk_valid.hex", "r") as fh:
        pk = bytes.fromhex(fh.read().strip())
    with open("sk_valid.hex", "r") as fh:
        sk = bytes.fromhex(fh.read().strip())
    return pk, sk


def sign(ser, msg):
    ser.write(REQUEST_SIGN + msg)
    status = ser.read(1)
    if len(status) != 1 or status[0] != 0:
        raise RuntimeError(f"sign FAILED (status={status!r})")
    sig = ser.read(SIGNATURE_SIZE)
    if len(sig) != SIGNATURE_SIZE:
        raise RuntimeError(f"short signature read ({len(sig)} bytes)")
    return sig


def verify_on_device(ser, sig, msg):
    """Round-trip through the board's own CMD_SW_FALCON_VERIFY (0x9D) -
    independent of the sign() call, using the device's own verifier rather
    than trusting the sign path alone."""
    ser.write(REQUEST_VERIFY + sig + msg)
    status = ser.read(1)
    return len(status) == 1 and status[0] == 0


def plot(power, trig, shot, msg, ok_verify, ok_repeat, scope, out_dir):
    t_ms = (np.arange(len(power)) - scope.n_pre) / scope.fs * 1e3
    power_mV = power / scope.maxadc.value * A_RANGE_V * A_PROBE * 1e3
    trig_V = trig / scope.maxadc.value * B_RANGE_V * B_PROBE

    fig, ax1 = plt.subplots(figsize=(12, 5))
    ax1.plot(t_ms, power_mV, color="C0", lw=0.5, label="power (chan A)")
    ax1.set_xlabel("time (ms)")
    ax1.set_ylabel("chan A power (mV)", color="C0")
    ax1.tick_params(axis="y", labelcolor="C0")

    ax2 = ax1.twinx()
    ax2.plot(t_ms, trig_V, color="C3", lw=0.8, alpha=0.6, label="trigger (chan B)")
    ax2.set_ylabel("chan B trigger (V)", color="C3")
    ax2.tick_params(axis="y", labelcolor="C3")

    bits = []
    if ok_repeat is not None:
        bits.append("repeat-sig OK" if ok_repeat else "repeat-sig MISMATCH")
    bits.append("device-verify OK" if ok_verify else "device-verify FAIL")
    ax1.set_title(f"Falcon sign #{shot}  msg={msg!r}  ({', '.join(bits)})")
    fig.tight_layout()
    out = os.path.join(out_dir, f"falcon_capture_{shot:02d}.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "falcon_captures", datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    os.makedirs(out_dir, exist_ok=True)
    print(f"Output folder: {out_dir}")

    print("Loading pk_valid.hex/sk_valid.hex ... ", end="")
    pk, sk = load_valid_key()
    print("OK")

    print(f"Opening serial port {port} ... ", end="")
    ser = serial.Serial(port=port, baudrate=115200, timeout=5.0)
    sleep(0.3)
    ser.reset_input_buffer()
    print("OK")

    print("Setting keypair on Pinata ... ", end="")
    write_chunked(ser, REQUEST_SET_KEY + pk + sk)
    status = ser.read(1)
    if len(status) != 1 or status[0] != 0:
        raise SystemExit(f"FAILED (status={status!r})")
    print("OK")

    print("Opening PicoScope 3000a ... ")
    scope = Scope()
    print("OK\n")

    cases = build_cases()
    signatures = []
    messages_hex = []
    signatures_hex = []
    n_repeat_ok = 0
    n_verify_ok = 0

    try:
        for shot, msg in enumerate(cases, start=1):
            scope.arm()
            # A small gap here avoids overlapping the scope-arm USB
            # transaction with the very next serial write - back-to-back
            # USB activity to two different devices (especially if they
            # share a hub) has corrupted the Pinata write and wedged its
            # get_bytes() mid-command in testing.
            sleep(0.05)
            sig = sign(ser, msg)
            power, trig = scope.read()
            ok_verify = verify_on_device(ser, sig, msg)
            n_verify_ok += ok_verify

            ok_repeat = None
            if shot <= SAME_MSG_RUNS and shot > 1:
                ok_repeat = (sig == signatures[0])
                n_repeat_ok += ok_repeat
            signatures.append(sig)

            kind = "same-msg" if shot <= SAME_MSG_RUNS else "diff-msg"
            print(f"  shot {shot:2d} [{kind}] msg={msg!r}")
            bits = []
            if ok_repeat is not None:
                bits.append(f"repeat-sig {'OK' if ok_repeat else 'MISMATCH'}")
            bits.append(f"device-verify {'OK' if ok_verify else 'FAIL'}")
            print(f"           {', '.join(bits)}")

            png = plot(power, trig, shot, msg, ok_verify, ok_repeat, scope, out_dir)
            print(f"           saved -> {png}")

            messages_hex.append(msg.hex())
            signatures_hex.append(sig.hex())
            if shot < len(cases):
                sleep(DELAY_S)
    finally:
        scope.close()
        ser.close()

    with open(os.path.join(out_dir, "messages.hex"), "w") as fh:
        fh.write("\n".join(messages_hex) + "\n")
    with open(os.path.join(out_dir, "signatures.hex"), "w") as fh:
        fh.write("\n".join(signatures_hex) + "\n")

    print(f"\n{n_repeat_ok}/{SAME_MSG_RUNS - 1} repeat signatures matched shot 1 "
          f"(determinism check, cases 2-{SAME_MSG_RUNS}).")
    print(f"{n_verify_ok}/{len(cases)} signatures verified OK on-device.")
    print(f"All output saved under {out_dir}")


if __name__ == "__main__":
    main()
