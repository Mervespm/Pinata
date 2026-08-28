"""PicoScope 3000a-series block-capture wrapper for the Pinata/Falcon SCA rig.

Mirrors the shape of HMAC_SCA/SCA_scripts/pico_scope.py (arm() then read()),
adapted from the newer ps6000a "unified" API to the older ps3000a legacy API
that the 3000a-series driver actually uses (ps3000aOpenUnit/SetChannel/
SetSimpleTrigger/RunBlock/GetValues/... instead of ps6000a's PicoDevice-style
calls). Channel A = power (current probe), channel B = trigger (PC2).

  from pico_scope_3000a import Scope
  scope = Scope()
  scope.arm(); ...; power, trig = scope.read(); scope.close()

Close the PicoScope GUI / Riscure Inspector first - only one program can own
the scope at a time.
"""
import ctypes
import os
from time import sleep

import numpy as np

# picosdk's ctypes loader resolves "ps3000a.dll" via the first match on PATH.
# On this machine that resolves to a 32-bit copy bundled with PicoScope6
# (Program Files (x86)), which fails to load into 64-bit Python with
# "WinError 193: not a valid Win32 application". Force it to find the known
# 64-bit copy (the same one Riscure Inspector uses successfully) first.
_PICO_64BIT_DIR = r"C:\Program Files\Inspector-2026.4-sca-fi\lib\Win64"
if os.path.isdir(_PICO_64BIT_DIR):
    os.environ["PATH"] = _PICO_64BIT_DIR + os.pathsep + os.environ["PATH"]

from picosdk.ps3000a import ps3000a as ps          # noqa: E402
from picosdk.functions import assert_pico_ok, mV2adc  # noqa: E402

# =============================== SETTINGS =============================== #
# channel A = power (current probe)
A_COUPLING = "DC"
A_RANGE_V  = 1
A_PROBE    = 1
# channel B = trigger (Pinata PC2, straight logic-level connection assumed)
B_COUPLING = "DC"
B_RANGE_V  = 5.0
B_THRESH_V = 1.0
B_PROBE    = 1

WINDOW_MS       = 320   # must comfortably cover the whole widened-trigger pulse
PRE_TRIG_FRAC   = 0.05  # small baseline captured before the B rising edge
TARGET_SAMPLES  = 200_000  # ceiling used to pick a timebase for WINDOW_MS
CAPTURE_TIMEOUT_S = 5.0
# "B" = trigger on channel B (digitized, returned as trig_B by read()).
# "EXTERNAL" = trigger on the dedicated EXT input - doesn't consume the 2nd
# ADC, so this scope hits a faster single-channel rate; no trig array back.
TRIGGER_SOURCE  = "EXTERNAL" 

RANGE_INDEX = {0.01: 0, 0.02: 1, 0.05: 2, 0.1: 3, 0.2: 4, 0.5: 5,
               1.0: 6, 2.0: 7, 5.0: 8, 10.0: 9, 20.0: 10, 50.0: 11}


class Scope:
    """ps3000a block-capture wrapper: arm() then read() one trace."""

    def __init__(self, window_ms=WINDOW_MS, pre_trig_frac=PRE_TRIG_FRAC,
                 trigger_source=TRIGGER_SOURCE, verbose=True):
        self.trigger_source = trigger_source
        self.handle = ctypes.c_int16()
        assert_pico_ok(ps.ps3000aOpenUnit(ctypes.byref(self.handle), None))

        self.maxadc = ctypes.c_int16()
        assert_pico_ok(ps.ps3000aMaximumValue(self.handle, ctypes.byref(self.maxadc)))

        self.chA = ps.PS3000A_CHANNEL["PS3000A_CHANNEL_A"]
        self.chB = ps.PS3000A_CHANNEL["PS3000A_CHANNEL_B"]
        self.chExt = ps.PS3000A_CHANNEL["PS3000A_EXTERNAL"]
        none_mode = ps.PS3000A_RATIO_MODE["PS3000A_RATIO_MODE_NONE"]
        self.none_mode = none_mode

        assert_pico_ok(ps.ps3000aSetChannel(self.handle, self.chA, 1,
                       ps.PS3000A_COUPLING["PS3000A_" + A_COUPLING], RANGE_INDEX[A_RANGE_V], 0.0))

        rising = ps.PS3000A_THRESHOLD_DIRECTION["PS3000A_RISING"]
        if trigger_source == "B":
            assert_pico_ok(ps.ps3000aSetChannel(self.handle, self.chB, 1,
                           ps.PS3000A_COUPLING["PS3000A_" + B_COUPLING], RANGE_INDEX[B_RANGE_V], 0.0))
            # mV2adc() has no notion of probe attenuation - it just scales
            # linearly against the channel range. B_THRESH_V is the intended
            # threshold AT THE PROBE TIP, so divide out B_PROBE before
            # converting to get the correct value at the scope's input.
            thr = mV2adc(B_THRESH_V / B_PROBE * 1000.0, RANGE_INDEX[B_RANGE_V], self.maxadc)
            assert_pico_ok(ps.ps3000aSetSimpleTrigger(self.handle, 1, self.chB, thr, rising, 0, 0))
        elif trigger_source == "EXTERNAL":
            # B not needed as a digitized channel - disabling it frees the
            # 2nd ADC, unlocking a faster single-channel rate.
            assert_pico_ok(ps.ps3000aSetChannel(self.handle, self.chB, 0,
                           ps.PS3000A_COUPLING["PS3000A_DC"], RANGE_INDEX[1.0], 0.0))
            # EXTERNAL threshold is expressed against a fixed +/-5V front end
            # (see HMAC_SCA/SCA_scripts/picoscopeMethods.py's setTrigger),
            # not the analog channel range settings.
            thr = mV2adc(B_THRESH_V / B_PROBE * 1000.0, RANGE_INDEX[5.0], self.maxadc)
            assert_pico_ok(ps.ps3000aSetSimpleTrigger(self.handle, 1, self.chExt, thr, rising, 0, 0))
        else:
            raise ValueError(f"trigger_source must be 'B' or 'EXTERNAL', got {trigger_source!r}")

        # Find a timebase whose window comfortably fits under TARGET_SAMPLES,
        # by asking the driver directly rather than assuming a rate formula
        # (the fs-vs-timebase law differs across 3000a-series sub-models).
        window_s = window_ms / 1000.0
        interval_ns = ctypes.c_float(0)
        max_samples = ctypes.c_int32(0)
        timebase = 0
        while True:
            status = ps.ps3000aGetTimebase2(self.handle, timebase, 2,
                                            ctypes.byref(interval_ns), 0,
                                            ctypes.byref(max_samples), 0)
            if status == 0:
                n = int(window_s / (interval_ns.value * 1e-9))
                if n <= TARGET_SAMPLES:
                    break
            timebase += 1
            if timebase > 200000:
                raise RuntimeError("no valid timebase found for this window/sample cap")
        self.timebase = timebase
        self.fs = 1e9 / interval_ns.value
        self.n_samples = int(window_s * self.fs)
        self.n_pre = int(self.n_samples * pre_trig_frac)
        self.n_post = self.n_samples - self.n_pre

        if verbose:
            print(f"Scope: {self.fs/1e6:.3f} MS/s (timebase {self.timebase}), "
                  f"{self.n_samples} samples = {window_ms} ms window "
                  f"(pre-trig {self.n_pre})")

        self.bufA = (ctypes.c_int16 * self.n_samples)()
        assert_pico_ok(ps.ps3000aSetDataBuffer(self.handle, self.chA,
                       ctypes.byref(self.bufA), self.n_samples, 0, self.none_mode))
        if trigger_source == "B":
            self.bufB = (ctypes.c_int16 * self.n_samples)()
            assert_pico_ok(ps.ps3000aSetDataBuffer(self.handle, self.chB,
                           ctypes.byref(self.bufB), self.n_samples, 0, self.none_mode))
        else:
            self.bufB = None

    def arm(self):
        """Start a block capture (returns immediately; trigger fires it)."""
        assert_pico_ok(ps.ps3000aRunBlock(self.handle, self.n_pre, self.n_post,
                                          self.timebase, 0, None, 0, None, None))

    def read(self):
        """Wait for the trigger, then return (power_A, trig_B) raw-ADC arrays.
        trig_B is None when trigger_source == 'EXTERNAL' (not a digitized
        channel, so there's nothing to plot as a trigger reference)."""
        ready = ctypes.c_int16(0)
        waited = 0.0
        assert_pico_ok(ps.ps3000aIsReady(self.handle, ctypes.byref(ready)))
        while ready.value == 0:
            sleep(0.005)
            waited += 0.005
            if waited > CAPTURE_TIMEOUT_S:
                ps.ps3000aStop(self.handle)
                raise TimeoutError("trigger never fired - check B_THRESH_V / wiring/trigger_source")
            assert_pico_ok(ps.ps3000aIsReady(self.handle, ctypes.byref(ready)))
        n = ctypes.c_uint32(self.n_samples)
        overflow = ctypes.c_int16(0)
        assert_pico_ok(ps.ps3000aGetValues(self.handle, 0, ctypes.byref(n), 1,
                                           self.none_mode, 0, ctypes.byref(overflow)))
        power = np.array(self.bufA, dtype=np.float64)
        trig = np.array(self.bufB, dtype=np.float64) if self.bufB is not None else None
        return power, trig

    def close(self):
        """Stop and disconnect the PicoScope."""
        ps.ps3000aStop(self.handle)
        ps.ps3000aCloseUnit(self.handle)
