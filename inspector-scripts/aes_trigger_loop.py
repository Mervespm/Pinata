"""
Minimal, Inspector-free trigger generator for Pinata's classic software
AES-128 command (CMD_SWAES128_ENC). Same idea as falcon_trigger_loop.py,
but for the simplest possible Pinata example: encrypt a fixed 16-byte
plaintext with the board's built-in default AES key, repeatedly, so you
can validate your scope/probe/trigger setup on a well-known, simple
target before going back to Falcon.

This needs the "hw" firmware (classic AES/DES/etc.), NOT the "pqc"
(Falcon) firmware - they are two different .dfu images built from the
same repo. Flash Pinata/build/src/hw.dfu before running this script.

Protocol (see main.c, case CMD_SWAES128_ENC):
    host -> board: 0xAE + 16 bytes plaintext
    board -> host: 16 bytes ciphertext (no separate status byte)
Trigger (GPIO PC2) is toggled inside AES128_ECB_encrypt(), after AES key
expansion, bracketing just the AES rounds - a short, simple, and highly
regular trigger pulse that's a good sanity check for your setup.

The board's default AES-128 key (see defaultKeyAES in main.c) is:
    ca fe ba be de ad be ef 00 01 02 03 04 05 06 07

Usage:
    python aes_trigger_loop.py [COM_PORT] [DELAY_SECONDS] [COUNT]

Defaults: COM6, 0.5, infinite (Ctrl+C to stop)
"""

import sys
import time

import serial

PLAINTEXT_SIZE = 16
CIPHERTEXT_SIZE = 16

REQUEST_AES_ENC = b"\xAE"

# Fixed plaintext - doesn't matter what it is, just needs to be 16 bytes.
PLAINTEXT = bytes(range(16))


def main() -> None:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    max_count = int(sys.argv[3]) if len(sys.argv) > 3 else None

    print(f"Opening serial port {port} ... ", end="")
    with serial.Serial(port=port, baudrate=115200, timeout=5.0) as ser:
        print("OK")

        if max_count is not None:
            print(f"\nEncrypting {max_count} times, every {delay}s - watch the trigger/trace on your scope now.\n")
        else:
            print(f"\nEncrypting repeatedly every {delay}s - watch the trigger/trace on your scope now.")
            print("Press Ctrl+C to stop.\n")

        count = 0
        try:
            while max_count is None or count < max_count:
                ser.write(REQUEST_AES_ENC + PLAINTEXT)
                ciphertext = ser.read(CIPHERTEXT_SIZE)
                if len(ciphertext) != CIPHERTEXT_SIZE:
                    print(f"[{count}] short/empty response ({len(ciphertext)} bytes) - is hw.dfu flashed and the board running?")
                else:
                    count += 1
                    print(f"[{count}] encrypted OK, ciphertext = {ciphertext.hex()}")
                time.sleep(delay)
        except KeyboardInterrupt:
            pass
        print(f"\nDone: {count} successful encryptions.")


if __name__ == "__main__":
    main()
