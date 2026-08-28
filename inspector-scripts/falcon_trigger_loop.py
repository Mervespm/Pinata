

import json
import sys
import time

import serial

MESSAGE_SIZE = 16
PUBLIC_KEY_SIZE = 897
PRIVATE_KEY_SIZE = 1281
SIGNATURE_SIZE = 666

REQUEST_SET_KEY = b"\x9B"
REQUEST_SIGN = b"\x9C"


def load_valid_key():
    """Load a plain (pk_valid.hex, sk_valid.hex) pair from the current directory.

    Each .hex file holds the key bytes as a plain hex string (no "0x", no
    spaces, no newlines needed - e.g. "09a1b2c3..."), which is easier to
    open, diff or edit by hand than a raw .bin file.
    """
    with open("pk_valid.hex", "r") as fh:
        pk = bytes.fromhex(fh.read().strip())
    with open("sk_valid.hex", "r") as fh:
        sk = bytes.fromhex(fh.read().strip())
    return pk, sk


def load_kat_key():
    """Load the KAT secret key (kat_sk.hex) paired with pk_valid.hex.

    kat_sk.hex holds the same secret key as sk_valid.hex (see gen_kat.c) -
    pk_valid.hex is its matching public key.
    """
    with open("pk_valid.hex", "r") as fh:
        pk = bytes.fromhex(fh.read().strip())
    with open("kat_sk.hex", "r") as fh:
        sk = bytes.fromhex(fh.read().strip())
    return pk, sk


def load_kat_messages():
    """Load the 5 fixed 16-byte KAT messages from kat_messages.hex, one per line."""
    with open("kat_messages.hex", "r") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    return [bytes.fromhex(line) for line in lines]


def load_first_key(prefix: str):
    """Load just the first (pk, sk) pair from a host_keygen key set."""
    with open(prefix + ".meta.json", "r") as fh:
        meta = json.load(fh)
    record_size = meta["record_size"]
    fields = meta["fields"]
    with open(prefix + ".bin", "rb") as fh:
        data = fh.read()
    if len(data) < record_size:
        raise ValueError(f"{prefix}.bin has no records")

    def field(name: str) -> bytes:
        spec = fields[name]
        return data[spec["offset"]:spec["offset"] + spec["size"]]

    return field("pk"), field("sk")


def main() -> None:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    key_source = sys.argv[2] if len(sys.argv) > 2 else "valid"
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
    max_count = int(sys.argv[4]) if len(sys.argv) > 4 else None

    is_kat = key_source == "kat"

    if key_source == "valid":
        print("Loading pk_valid.hex/sk_valid.hex ... ", end="")
        pk, sk = load_valid_key()
    elif is_kat:
        print("Loading pk_valid.hex/kat_sk.hex ... ", end="")
        pk, sk = load_kat_key()
    else:
        print(f"Loading first key from {key_source}.bin/.meta.json ... ", end="")
        pk, sk = load_first_key(key_source)
    if len(pk) != PUBLIC_KEY_SIZE or len(sk) != PRIVATE_KEY_SIZE:
        print("FAILED")
        raise SystemExit(f"unexpected key sizes: pk={len(pk)}, sk={len(sk)}")
    print("OK")

    if is_kat:
        print("Loading kat_messages.hex ... ", end="")
        messages = load_kat_messages()
        for i, msg in enumerate(messages):
            if len(msg) != MESSAGE_SIZE:
                print("FAILED")
                raise SystemExit(f"message {i} is {len(msg)} bytes, expected {MESSAGE_SIZE}")
        print(f"OK ({len(messages)} messages)")

    print(f"Opening serial port {port} ... ", end="")
    with serial.Serial(port=port, baudrate=115200, timeout=5.0) as ser:
        print("OK")

        # If a previous run was Ctrl+C'd while waiting on a response, the
        # board may still have finished that operation and sent its bytes
        # after we stopped listening - they'd sit unread and desync every
        # read below (each read would consume leftover bytes from the old
        # response instead of the real answer to the new command). Discard
        # anything already buffered before sending our first command.
        ser.reset_input_buffer()

        print("Setting keypair on Pinata ... ", end="")
        ser.write(REQUEST_SET_KEY + pk + sk)
        status = ser.read(1)
        if len(status) != 1 or status[0] != 0:
            raise SystemExit(f"FAILED (status={status!r})")
        print("OK")

        if is_kat:
            print(f"\nSigning all {len(messages)} KAT messages on the device ...\n")
            device_signatures = []
            for i, msg in enumerate(messages):
                ser.write(REQUEST_SIGN + msg)
                status = ser.read(1)
                if len(status) != 1 or status[0] != 0:
                    print(f"[{i}] sign FAILED (status={status!r}) for message={msg!r}")
                    device_signatures.append(None)
                else:
                    sig = ser.read(SIGNATURE_SIZE)
                    if len(sig) != SIGNATURE_SIZE:
                        print(f"[{i}] short signature read ({len(sig)} bytes) for message={msg!r}")
                        device_signatures.append(None)
                    else:
                        device_signatures.append(sig)
                        print(f"[{i}] message={msg!r}")
                        print(f"     signature ({SIGNATURE_SIZE} bytes):")
                        print(f"     {sig.hex()}")
                time.sleep(delay)

            ok_count = sum(1 for s in device_signatures if s is not None)
            print(f"\nDone: {ok_count}/{len(messages)} signed OK.")

            with open("device_signatures.hex", "w") as fh:
                for sig in device_signatures:
                    fh.write((sig.hex() if sig is not None else "") + "\n")
            print("Wrote device_signatures.hex (compare against kat_signatures.hex - "
                  "bytes will differ since the device uses its own random seed per "
                  "sign, but each should still verify against pk_valid.hex).")
            return

        message = b"TriggerLoopTest!"  # exactly 16 bytes
        assert len(message) == MESSAGE_SIZE

        if max_count is not None:
            print(f"\nSigning {max_count} times, every {delay}s - watch the trigger/trace on your scope now.\n")
        else:
            print(f"\nSigning repeatedly every {delay}s - watch the trigger/trace on your scope now.")
            print("Press Ctrl+C to stop.\n")

        count = 0
        try:
            while max_count is None or count < max_count:
                ser.write(REQUEST_SIGN + message)
                status = ser.read(1)
                if len(status) != 1 or status[0] != 0:
                    # A short/empty read here almost always means a byte got
                    # corrupted or dropped on the wire (e.g. a bumped cable or
                    # probe), which permanently shifts read alignment for
                    # every command after it. There's no resync in this
                    # simple protocol, so without a flush this would fail
                    # forever - clear whatever's buffered so the next
                    # iteration starts clean instead of staying desynced.
                    ser.reset_input_buffer()
                    print(f"[{count}] sign FAILED (status={status!r}) - flushed input buffer, retrying next iteration")
                else:
                    sig = ser.read(SIGNATURE_SIZE)
                    if len(sig) != SIGNATURE_SIZE:
                        ser.reset_input_buffer()
                        print(f"[{count}] short signature read ({len(sig)} bytes) - flushed input buffer, retrying next iteration")
                    else:
                        count += 1
                        print(f"[{count}] signed OK ({SIGNATURE_SIZE}-byte signature received)")
                time.sleep(delay)
        except KeyboardInterrupt:
            pass
        print(f"\nDone: {count} successful signs.")


if __name__ == "__main__":
    main()
