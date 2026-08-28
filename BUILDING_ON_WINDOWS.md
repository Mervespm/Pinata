# Building Pinata on Windows (native, no WSL)

This covers building the `pqc` firmware (ML-DSA + ML-KEM + Falcon/FN-DSA)
directly on Windows. The toolchain-file and CMake fixes needed for this are
already committed in this repo - you only need the one-time prerequisites
below, then two commands.

## One-time setup

1. **Enable Windows Developer Mode.** Settings -> Privacy & security -> For
   developers -> Developer Mode: On.

   This is required because `pqm4` (a dependency fetched during configure)
   shares source files between parameter sets using real Unix symlinks.
   Without Developer Mode, Windows silently checks these out as plain text
   files containing the link target path instead of real symlinks, and the
   build fails with errors like:
   ```
   error: expected identifier or '(' before '.' token
       1 | ../../ml-dsa-44/m4f/poly.c
   ```
   or, for assembly files:
   ```
   Error: unknown pseudo-op: `..'
   ```
   If you see either of those, this is almost certainly the cause.

2. **Tell Git to actually create symlinks:**
   ```powershell
   git config --global core.symlinks true
   ```
   (Do this *before* cloning/configuring, or delete `build/_deps/pqm4-src`
   and reconfigure afterward - Git only checks out real symlinks going
   forward, existing checkouts don't self-heal.)

3. **Install the Arm GNU Toolchain** (`arm-none-eabi-gcc`):
   ```powershell
   winget install --id Arm.ArmGnuToolchain
   ```
   Note the install path it prints, e.g.:
   ```
   C:\Program Files (x86)\Arm GNU Toolchain arm-none-eabi\<version>\bin\
   ```
   Open a **new** terminal afterward so PATH changes take effect.

4. **(Only if you need to flash the board)** Install `dfu-util`: download
   `dfu-util-0.11-binaries.tar.xz` from the official releases at
   `sourceforge.net/projects/dfu-util/files/dfu-util/0.11/`, extract it, and
   put the `win64\` folder's `dfu-util.exe`, `dfu-suffix.exe`, and
   `libusb-1.0.dll` somewhere on your PATH.

## Build

```powershell
cmake -DCMAKE_TOOLCHAIN_FILE=gcc-arm-none-eabi.toolchain.cmake -S . -B build `
  -DPREFIX="C:/Program Files (x86)/Arm GNU Toolchain arm-none-eabi/<version>/bin/arm-none-eabi-"

cmake --build build --target pqc
```

- `-DPREFIX` is required - the toolchain file's built-in default
  (`/usr/bin/arm-none-eabi-`) is a Unix path and silently won't resolve on
  Windows. Replace `<version>` with whatever winget installed (check the
  path from step 3).
- Output: `build/src/pqc.elf` (and `build/src/pqc.dfu` if `dfu-util` was
  found on PATH when you ran the `cmake -S ... -B build` command).
- First configure will take ~40s - it's fetching `pqm4` and its submodules
  (`mupq`, and `mupq`'s own nested `pqclean` submodule) over git.

## Flashing

```powershell
cmake --build build --target pqc_flash
```

Needs the board physically connected in DFU mode, and `dfu-util` on PATH.
On Windows, `dfu-util` talks to the device over **libusb**, not the ST DFU
class driver Windows binds by default - you'll likely need
[Zadig](https://zadig.akeo.ie/) to rebind the DFU-mode USB device (VID
`0483`, PID `DF11`) to **WinUSB** once.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `expected identifier or '(' before '.' token` | Symlinks not real - see step 1/2 |
| `is not a full path to an existing compiler tool` | Missing/wrong `-DPREFIX`, or old checkout without the `.exe`-suffix fix |
| `dfu-suffix was not found in $PATH` at configure time | `dfu-util` not installed/not on PATH yet - harmless if you're not flashing |
| `region 'ram' overflowed` | Something's using more static RAM than fits - see how Falcon's signing scratch buffer was moved from static RAM to the call stack in `src/falcon/wrapper.c` (`fndsa_sign_seeded` vs the `_temp` variant) if you hit this again |
| `Could not find toolchain file: gcc-arm-none-eabi` (missing the `.toolchain.cmake` part, and a stray `Ignoring extra path from command line: .toolchain.cmake` warning) | Pass `-DCMAKE_TOOLCHAIN_FILE` as an **absolute path**, not the bare relative filename - CMake mishandles the relative dotted filename in this setup. E.g. in PowerShell: `-DCMAKE_TOOLCHAIN_FILE=$(Resolve-Path .\gcc-arm-none-eabi.toolchain.cmake)` |
| `Could NOT find Git (missing: GIT_EXECUTABLE)` at configure time | `git` isn't on `PATH` in this shell even if it's installed (e.g. `C:\Users\<you>\AppData\Local\Programs\Git\bin`) - add it to `PATH` for the session before configuring; needed to fetch `pqm4` |

**Verified 2026-08-21:** a clean `build/` (toolchain absolute path + git on PATH, per above) configures and `cmake --build build --target pqc` completes 88/88, producing `build/src/pqc.elf` - including the patched `sign.c` with `PINATA_PATCH_falcon_decode_start/finish_callback()` confirmed present in the compiled source. The firmware side compiles cleanly; only actual hardware flashing/tracing is still unverified (no board yet).

## Side-channel attack setup (Falcon f/g leakage)

This is the reference for the profiled side-channel attack setup, kept
here so it doesn't get scattered across chat history. Covers what's built,
what's verified, and the current plan. Update this section as the setup
evolves.

### What's being targeted

`src/falcon/wrapper.c`'s `FalconState_sign()` calls `fndsa_sign_seeded()`,
which (via `patches/fndsa-sign.patch`) toggles GPIO PC2 tightly around
exactly one call: `trim_i8_decode(logn, sign_key + j, f, nbits)` in
`fndsa_provisional-512/m4f/sign.c` - the loop that unpacks the 512
coefficients of the secret polynomial `f` from its packed 6-bit-per-
coefficient encoding (`g` and `F` decode afterward, untraced). This is
confirmed against the real source (not assumed):
`fndsa_provisional-512/m4f/sign.c` picks `nbits=6` for `logn=9`
(Falcon-512/FN-DSA-512), and `codec.c`'s `trim_i8_decode()` sign-extends
each field with `w |= -(w & mask2)` on a `uint32_t` before truncating to
`int8_t` on the store - this is the exact leak-point structure (A: byte
load, B: field extraction, C: sign-extension, D: truncating store) the
leakage simulation work was built around.

Because `f` and `g` are 6-bit fields packed into 8-bit bytes (6 doesn't
divide 8), decoding them crosses byte boundaries - adjacent coefficients
share bytes, which is a free joint constraint `F` doesn't get (it's 8-bit,
byte-aligned). That's *why* `f` (traced here) is the right first target,
not `F`.

### Current plan: profile coefficient `f[0]` first, not all 512

Rather than trying to profile all 512 coefficients of `f` at once, the
plan is to first get one coefficient working end-to-end:

1. Validates the whole pipeline (known-key generation -> acquisition ->
   per-trace ground-truth labeling -> template building -> recovery) on a
   ~63-value problem (f[0] in [-31, 31], with the forbidden Falcon field
   value excluded) instead of the much harder full-cycle joint recovery.
2. **No code change was needed for this** - every acquired trace is
   already labeled with the full `F_COEFFS` array (see below), so
   targeting f[0] is purely an analysis-stage choice: read
   `F_COEFFS[0]` as the label, ignore the rest.
3. The GPIO trigger is *not* being narrowed to f[0] specifically yet.
   `trim_i8_decode(f)`'s loop processes coefficients in order, so f[0]'s
   leakage is at the very start of the existing captured window - the
   current (whole-array) trigger already captures it. A tighter,
   coefficient-0-only trigger (would need a new patch touching `codec.c`,
   since that file is vendored/fetched, not part of `src/`) is a
   reasonable follow-up once real trace data shows where f[0] actually
   sits in the window and whether a tighter capture is worth it - not
   worth doing blind before that.
4. Once f[0] works, extend the same labeling/template approach to more
   coefficients (the byte-packing joint-constraint work applies to
   *pairs* of adjacent coefficients within a 4-coefficient/3-byte cycle,
   so f[1] is a natural second target - it shares a byte with f[0]).

### 1. Generate known keys (`tools/host_keygen`)

A profiled attack needs many *known* values of the coefficient being
targeted to correlate traces against - one fixed key can't build a
template. This tool generates real, valid FN-DSA-512 keys on the host PC
(no board needed) by reusing the actual on-device keygen/decode algorithm
- a frozen, portable-C copy of `build/_deps/pqm4-src/crypto_sign/
fndsa_provisional-512/m4f` (see `tools/host_keygen/fndsa/`, minus the
Cortex-M4 assembly `.s` files, which don't apply on a desktop host). It
also decodes/re-encodes `f`/`g` via the *actual* `trim_i8_decode()`/
`trim_i8_encode()` (compiled from the same source), so ground truth and
any modified keys stay guaranteed-consistent with what the firmware does
- nothing is reimplemented or approximated.

Build (separate, host-native CMake project - deliberately not part of the
top-level ARM cross-compile build):
```powershell
cmake -S Pinata\tools\host_keygen -B Pinata\tools\host_keygen\build
cmake --build Pinata\tools\host_keygen\build
```

**`sweep` mode - current phase, single-coefficient profiling:**
```powershell
Pinata\tools\host_keygen\build\host_keygen.exe sweep 0 falcon_sweep
```
Generates **one** real base key via `fndsa_keygen()`, decodes its `f`,
then for each of the 63 valid values of `f[0]` (every integer in
`-31..31` - the one forbidden 6-bit pattern maps to `-32`, outside that
range) rebuilds `f` with only index 0 changed and re-encodes it with
`trim_i8_encode()`, splicing only that back into a copy of the base
`sk`. `g`, `F`, the header byte, and `pk` are written byte-identical
across all 63 records - `pk` doesn't even need to be kept consistent
with the perturbed `f`, since `FalconState_sign()` never reads `pk` (only
`verify()` does, which acquisition never calls), and `G` isn't part of
the stored key at all - it's recomputed fresh from `f,g,F` on every
`sign()` call (`sign.c`'s `sign_step1()`), so there's no stale-`G`
consistency requirement to worry about either. Each record also gets a
round-trip self-check (decode the variant back, assert `f[0]==value` and
every other coefficient is untouched) before being written.

Verified independently (not just the tool's own self-check - a from-
scratch Python re-implementation of `trim_i8_decode` run directly against
the raw output bytes): for a real 63-record sweep, the independently
decoded `f[0]` ran exactly `-31..31` in order, `f[i]` for every `i != 0`
was bit-for-bit identical across all 63 records, and `g`/`pk` were
byte-identical across all 63 records. Example - `sk` bytes for
`f[0]=0` vs `f[0]=1`: **only offset 1 of the 1281-byte `sk` differs**
(`0x03 -> 0x07`), matching the known packing (`byte0 = 6 bits of f[0] +
top 2 bits of f[1]`): top 6 bits change (`000000`->`000001`, i.e. the
field for `f[0]`), bottom 2 bits stay `11` in both (`f[1]`'s untouched
contribution).

**`<num_keys>` mode - later phase, full/joint recovery:**
```powershell
Pinata\tools\host_keygen\build\host_keygen.exe 200 falcon_keys
```
Generates `num_keys` fully independent random keys instead (not a
sweep). Not the current focus - keep for when profiling moves beyond
`f[0]` alone.

Both modes write `<prefix>.bin` (back-to-back fixed-size records:
`pk`(897B) || `sk`(1281B) || `f`(512B int8) || `g`(512B int8)) and
`<prefix>.meta.json` (record layout, so nothing downstream hardcodes
offsets) - same format either way, so `falcon_sca_pinata.py`'s loader
doesn't care which mode produced its input. **Both files contain secret
key material - `*.bin` is already covered by the repo's gitignore rule,
but don't commit the `.meta.json` either if it's sitting next to real
keys.**

Build note: `fndsa/kgen.c`'s x86 AVX2 fast path (functions marked
`__attribute__((target("avx2")))`, `__m256i`-by-value args) segfaults on
entry under MinGW-w64/GCC 13 - a toolchain/ABI issue, not a bug in the
algorithm. `CMakeLists.txt` sets `FNDSA_AVX2=0` to force the plain
portable-C path instead (same algorithm the Cortex-M4 firmware itself
uses - it has no AVX2 either). Keygen only runs a handful of times, so
the lack of AVX2 speedup doesn't matter.

### 2. Acquire traces (`inspector-scripts/falcon_sca_pinata.py`)

Requires Inspector running (`riscure.inspector.connect()`) and a key set
from step 1. In the Inspector parameter dialog, point "Key set file
prefix" at the prefix you generated - default is `falcon_sweep` (the
current f[0]-sweep filename), matching `host_keygen sweep 0 falcon_sweep`
above.

The script cycles through the loaded keys during acquisition ("Traces per
key", default 200 - so with the 63-record f[0] sweep, "Total number of
measurements" defaults to 63 x 200 = 12600) - it is *not* one fixed key
for the whole trace set. Before each key's first trace, it calls
`set_public_private_key()`, then tags **every trace** with `PUBLIC_KEY`,
`PRIVATE_KEY`, `F_COEFFS`, and `G_COEFFS` as per-trace parameters (not one
trace-set-wide constant), since the profiled model needs to know the true
coefficient values for each individual trace it trains on. These
defaults are starting points, not measured requirements - tune
`traces_per_key` once real trace noise is known.

Not yet built: the analysis/template-building script itself (this
acquisition script only captures and labels traces). When that's
written, start it against `F_COEFFS[0]` only, per the plan above.

### 3. How traces get saved (Inspector `.trs` files)

This is handled by Inspector's own Python API, already wired up in
`main()`/`do_measurements()` - nothing extra to build:

- `write_op = ManualInputTraceSetSink(ins, source.trace_meta_data,
  file_name)` opens the output trace set, where `file_name =
  os.path.join(ins.settings.trace_set_path, parameters[trs_filename])` -
  i.e. Inspector's own configured trace-set directory
  (`ins.settings.trace_set_path`) plus the "Result file name" parameter
  (default `SCA Falcon Pinata Acquisition.trs`).
- `.trs` is Riscure's trace-set format: one file holding every captured
  waveform *and* its per-trace parameters together - there's no separate
  labels file to keep in sync.
- Inside `do_measurements()`, each captured trace is written with
  `write_job.put(trace)` after its parameters are attached
  (`trace.parameters["MESSAGE"] = ...`, `["F_COEFFS"] = ...`, etc.) -
  so every trace in the resulting `.trs` already carries its own ground
  truth (message, signature, full public/private key, decoded f/g) right
  alongside the waveform samples.
- The finished `.trs` file is what you'd open directly in Inspector's GUI
  afterward for inspection, CPA, or template building - or read
  programmatically for a custom analysis script (not yet built - see
  Status below).

### Status

- [x] Firmware trigger reviewed against real source - correctly brackets
      only `f`'s decode.
- [x] Firmware **verified to compile end-to-end** (`cmake --build build
      --target pqc`, 88/88, `build/src/pqc.elf` produced) - see
      Troubleshooting above for the two gotchas hit getting there.
- [x] Host-side known-key generation, verified against real bounds
      (random mode) and independently verified byte-for-byte as a clean
      single-variable experiment (sweep mode).
- [x] Acquisition script supports many known keys + per-trace ground
      truth labeling, defaulted to the f[0] sweep.
- [ ] Physical board not yet received - nothing above has been run
      against real hardware/traces yet.
- [ ] Analysis/template-building script (targets `F_COEFFS[0]` first).
