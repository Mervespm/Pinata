# Falcon f[0] demo — self-contained, profiled on the current firmware

A profiled template only transfers within **one** measurement setup. The main
`template_attack/templates.npz` (the 99% result) was profiled on an earlier
capture campaign, so it does **not** read traces from today's firmware. This
folder rebuilds the whole chain on the *current* firmware + scope config, so the
demo works end-to-end. Nothing outside this folder is touched.

All traces are captured into `C:/Users/mervkara/Inspector/data/demo/`.

Scope config (identical across every step, the one that gives clean ±60 traces):
`Channel A 0.2 V · 200000 samples @ 1000 MHz · External trigger 1 V · decode trigger on device`.

## Run order

```
python falcon_profile_capture.py     # 1. sign many KNOWN keys  -> demo_profile.trs  (the training set)
python falcon_train.py               # 2. POIs + LDA/LogReg      -> templates.npz     (+ held-out accuracy)
python falcon_demo_capture.py        # 3. sign ONE known key N times -> demo_v2.trs   (the attack traces)
python falcon_test.py <demo_v2.trs>  # 4. recover f[0] from the demo capture
```

`falcon_test.py` with no argument auto-picks the newest `*demo_v2*.trs`.

## Notes

- **Same firmware for all steps.** Steps 1 and 3 must run on the same flashed
  firmware; the template from step 2 is only valid for that firmware.
- **`~name.trs` files.** If a target name already exists, Inspector writes
  `~name.trs` / `~name(2).trs`. `falcon_train.py` resolves these automatically;
  for `falcon_test.py` just pass the actual file it wrote.
- **Profile size.** `KEYS_PER_CLASS` in `falcon_profile_capture.py` sets traces
  per class (× 21 classes). 1000 = full 21000-trace profile; lower it for a
  quicker run.
- **Sanity gate.** After step 2, check the held-out accuracy it prints. If that
  is high but the demo still misses, the demo capture used a different
  firmware/config than the profile — recapture step 3 to match step 1.
