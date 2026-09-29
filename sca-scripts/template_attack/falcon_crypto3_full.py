
import os
import json

import numpy as np
import trsfile

import riscure.inspector
from riscure.inspector import SinkOperation, TraceSetSource


def _read_poi(path, poi):
    """Read a .trs, return {f0: [nTraces x nPOI]} at the given POI samples."""
    feat = {}
    with trsfile.trs_open(path, "r") as ts:
        for i in range(len(ts)):
            t = ts[i]
            f0 = int(np.frombuffer(bytes(t.parameters["f0"].value), np.int8)[0])
            feat.setdefault(f0, []).append(np.asarray(t.samples, np.float64)[poi])
    return {c: np.array(v) for c, v in feat.items()}


def build_and_print_template(learn_file, poi):
    """Print the arrays crypto3 works with (POIs, means, pooled covariance) and
    return the LDA discriminant (cls, W, b) so Apply's per-candidate scores can
    be reproduced (pooled Mean+Cov == LDA)."""
    np.set_printoptions(precision=2, suppress=True, linewidth=140)
    poi = list(poi)
    X = _read_poi(learn_file, poi)
    cls = sorted(X)
    mu = {c: X[c].mean(0) for c in cls}
    d = len(poi); Sw = np.zeros((d, d)); n = 0
    for c in cls:
        Z = X[c] - mu[c]; Sw += Z.T @ Z; n += len(Z)
    Sw /= n
    Si = np.linalg.pinv(Sw)
    W = {c: Si @ mu[c] for c in cls}                 # linear discriminant weights
    b = {c: -0.5 * mu[c] @ Si @ mu[c] for c in cls}  # per-class bias
    print("\n================ crypto3 arrays ================")
    print("POIs (SOST-selected, %d points):" % len(poi)); print(np.array(poi))
    print("\ntemplate MEANS  [%d classes x %d POIs]  (rows = f0):" % (len(cls), len(poi)))
    for c in cls:
        print("  f0=%+3d :" % c, mu[c])
    print("\npooled COVARIANCE  [%dx%d]  (6x6 corner):" % (d, d)); print(Sw[:6, :6])
    print("covariance diagonal (per-POI variance):"); print(np.diag(Sw))
    print("================================================\n")
    return cls, W, b


def apply_scores(test_file, true_f0, poi, cls, W, b):
    Xt = _read_poi(test_file, poi)[true_f0]
    score = {c: float((Xt @ W[c] + b[c]).sum()) for c in cls}   # accumulated over all traces
    order = sorted(cls, key=lambda c: -score[c]); top = score[order[0]]
    rank = order.index(true_f0) + 1
    margin = score[order[0]] - score[order[1]]                   # winner vs runner-up
    top6 = " ".join("%s%+d%s" % ("*" if c == true_f0 else "", c,
                                 "*" if c == true_f0 else "") for c in order[:6])
    print("      top guess = %+d  (rank of true = %d) | ranking: %s" % (order[0], rank, top6))
    return rank, order[0], margin

LEAK = "leak1"
AVG_N = os.environ.get("AVG_N", "")   # "" = raw ; "10"/"45" = use the averaged-by-N set
_base = {"leak1": "falcon_leak1_10k", "leak2": "falcon_leak2_10k"}[LEAK]
DATA_DIR = rf"C:\Users\mervkara\Inspector\data\{_base}{'_avg'+AVG_N if AVG_N else ''}_keyed"
LEARN_FILE = os.path.join(DATA_DIR, f"falcon_{LEAK}_LEARN_keyed.trs")
TEST_FILES = [os.path.join(DATA_DIR, f"falcon_{LEAK}_TEST_class{i:02d}_keyed.trs")
              for i in range(21)]
CLASS_F0 = list(range(-10, 11))

POI_SET_NAME = "falcon_f0_poi"
LEAK_MODEL = "ID Bits"
NUM_POI = 20
TEMPLATE_FILE_NAME = f"falcon_{LEAK}_f0_crypto3.templates"
POI_TARGET = "f0"
CLASSIFY_IDENTIFIER = "ID Bits[0,8] Key"  


if POI_TARGET == "hwmodq":
    LEARN_FILE = os.path.join(DATA_DIR, f"falcon_{LEAK}_LEARN_hwinput.trs")


def known_value_hex(f0: int) -> str:
    return format(f0 & 0xFF, "02X")


def inject_poi(meta_path: str, poi_name: str, poi_spec: dict) -> None:
    """Write a POI set into a .trs.meta JSON file, creating it if absent."""
    meta = {"regions": {}, "patterns": {}, "pointsOfInterest": {}, "version": 2}
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except (ValueError, OSError):
            pass
    meta.setdefault("pointsOfInterest", {})[poi_name] = poi_spec
    with open(meta_path, "w") as f:
        json.dump(meta, f)


def run(learn_file=LEARN_FILE):
    """Run Learn + Apply(21 classes). Returns accuracy (0..1)."""
    with riscure.inspector.connect() as ins:
        template_file = os.path.join(ins.settings.trace_set_path, TEMPLATE_FILE_NAME)

        key_func = ins.create_trace_parameters_function("TraceParameterKey")
        model = ins.create_leakage_model(LEAK_MODEL, {"firstBit": 0, "numberOfBits": 8})
        sel = ins.create_leakage_selection(model, key_func)  # classification: f0

        # POI-search selection: hw(f0 mod Q) via INPUT for leak2, else identity on f0.
        if POI_TARGET == "hwmodq":
            input_func = ins.create_trace_parameters_function("TraceParameterInput")
            poi_sel = ins.create_leakage_selection(model, input_func)
        else:
            poi_sel = sel

        # --- Step 1: POI SEARCH (SOST) on the Learn set - crypto3 selects the POIs ---
        print(f"... POI search (SOST, target={POI_TARGET}) on Learn set")
        poi_op = ins.create_operation("Points Of Interest Data Loading")
        poi_op.settings.leakageSelections = [poi_sel]
        poi_op.settings.numberOfResultPoints = NUM_POI
        poi_op.settings.method = "CORR"
        poi_op.settings.poiSetName = POI_SET_NAME
        wr = SinkOperation(ins, "Regions Writer")
        read_op = TraceSetSource(ins, learn_file)
        read_op.connect(poi_op)
        poi_op.connect(wr, "REGIONS")
        read_op.run().complete()
        with open(learn_file + ".meta") as f:
            learn_meta = json.load(f)
        poi_spec = learn_meta["pointsOfInterest"][POI_SET_NAME]
        print(f"    found as   : {poi_spec['leakageModelIdentifiers']}")
        poi_spec["leakageModelIdentifiers"] = [CLASSIFY_IDENTIFIER]

        # --- Step 2: inject the POI set into learn + every test file's meta ---
        inject_poi(learn_file + ".meta", POI_SET_NAME, poi_spec)  # learn needs it too
        for tf in TEST_FILES:
            inject_poi(tf + ".meta", POI_SET_NAME, poi_spec)
        print(f"    re-tagged to {CLASSIFY_IDENTIFIER}, injected into learn + {len(TEST_FILES)} test metas")

        # --- Step 3: Learn templates ---
        print("... Learning templates")
        learn_op = ins.create_operation("Template Analysis Data Loading Learning")
        learn_op.settings.leakageSelections = [sel]
        learn_op.settings.templateFile = template_file
        learn_op.settings.poiSetName = POI_SET_NAME
        learn_op.settings.templateSettings.model = "Mean+Cov"
        learn_op.settings.templateSettings.optimizer = "Pooled"
        read_op2 = TraceSetSource(ins, learn_file)
        read_op2.connect(learn_op)
        read_op2.run().complete()
        print(">> templates learned")

        # show the arrays crypto3 built: POIs, means, covariance (returns the LDA
        # discriminant so we can print Apply's full 21-candidate scores too)
        POI = poi_spec["indices"]
        cls, W, b = build_and_print_template(learn_file, POI)

        # --- Step 4: Apply per held-out class -
        results = []
        score_table = []   # (true, winner, rank, margin) for the write-up
        for f0, tf in zip(CLASS_F0, TEST_FILES):
            try:
                apply_op = ins.create_operation("Template Analysis Data Loading Apply")
                apply_op.settings.leakageSelections = [sel]
                apply_op.settings.templateFile = template_file
                apply_op.settings.poiSetName = POI_SET_NAME
                apply_op.settings.templateSettings.model = "Mean+Cov"
                apply_op.settings.templateSettings.optimizer = "Pooled"
                apply_op.settings.attackType = "Known Value"
                apply_op.settings.dataSourceOption = "Input field"
                apply_op.settings.dataInput = known_value_hex(f0)
                apply_op.settings.reportInterval = 100

                ranking_file = os.path.join(ins.settings.trace_set_path,
                                            f"c3_rank_class{f0:+d}.npy")
                wrk = SinkOperation(ins, "Number Array Writer")
                wrk.settings.fileName = ranking_file
                wrk.settings.overwrite = True

                ar = TraceSetSource(ins, tf)
                ar.connect(apply_op)
                apply_op.connect(wrk, "KNOWN_KEY_RANKING_OUT")
                ar.run().complete()

                rk = np.load(ranking_file)  # shape (n_intervals, 2) = [rank, confidence]
                final_rank = int(rk[-1, 0])
                final_conf = float(rk[-1, 1])
                ok = final_rank == 1
                results.append((f0, final_rank, ok))
                print(f"    f0={f0:+3d}: rank={final_rank:3d}  conf={final_conf:8.2f}  "
                      f"{'CORRECT' if ok else 'wrong'}")
                # full 21-candidate scores for this class (reproduces Apply's ranking)
                rnk, winner, margin = apply_scores(tf, f0, POI, cls, W, b)
                score_table.append((f0, winner, rnk, margin))
            except Exception as e:
                results.append((f0, None, False))
                print(f"    f0={f0:+3d}: ERROR {type(e).__name__}: {str(e)[:80]}")

        tested = [r for r in results if r[1] is not None]
        n_ok = sum(1 for r in results if r[2])

        # write the score table for the write-up (true vs winner vs margin)
        if score_table:
            tbl = os.path.join(ins.settings.trace_set_path, f"c3_score_table_{LEAK}.md")
            with open(tbl, "w") as f:
                f.write(f"# crypto3 {LEAK} per-class result (true vs winner vs margin)\n\n")
                f.write("| true f0 | rank | top guess | outcome |\n")
                f.write("|---|---|---|---|\n")
                for true, winner, rnk, margin in score_table:
                    out = "recovered" if rnk == 1 else f"collision -> lost to {winner:+d}"
                    f.write(f"| {true:+d} | {rnk} | {winner:+d} | {out} |\n")
            print(f"\nscore table written -> {tbl}")

        print()
        if tested:
            acc = n_ok / len(tested)
            print(f"=== {n_ok}/{len(tested)} classes recovered at Rank 1 "
                  f"-> accuracy = {acc:.1%} ===")
            return acc
        print("=== no classes completed ===")
        return 0.0


def main():
    run()


if __name__ == "__main__":
    main()
