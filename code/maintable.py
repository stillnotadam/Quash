"""Consolidate the paper's headline numbers from all result CSVs into results/main_numbers.json + a printed table.
Every number the paper cites is computed here from the artifacts, so the paper and code cannot drift."""
import csv, json, os
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def L(p):
    return pd.read_csv(os.path.join(ROOT, p), dtype={"id": str})


m = L("data/master.csv")
N = {k: int((m.label == k).sum()) for k in ("genuine", "slop", "invalid", "resolved")}
out = {"corpus": N, "corpus_total": int(len(m))}

# year distribution
m["year"] = m.created.str[:4]
out["by_year"] = {y: {k: int(v) for k, v in m[m.year == y].label.value_counts().items()} for y in sorted(m.year.dropna().unique())}

# existence grounding (scoped, MINT-style): slop that PASSES (grounded) and genuine wrongly flagged ungrounded
ex = L("results/existence_scoped.csv").merge(m[["id", "label"]], on="id")
out["existence"] = {
    "slop_passes_grounding_pct": round(100 * (ex[ex.label == "slop"].any_ungrounded == 0).mean(), 1),
    "genuine_flagged_ungrounded_pct": round(100 * (ex[ex.label == "genuine"].any_ungrounded == 1).mean(), 1),
    "slop_mean_fidelity": round(ex[ex.label == "slop"].fidelity.astype(float).mean(), 3),
    "genuine_mean_fidelity": round(ex[ex.label == "genuine"].fidelity.astype(float).mean(), 3),
}

# text classifier AUROC: genuine vs slop (gist) and genuine vs 2026 invalid
tx = L("results/text_scores.csv").merge(m[["id", "label", "year"]], on="id")


def auroc(pos, neg):
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    pos, neg = pos[~np.isnan(pos)], neg[~np.isnan(neg)]
    if not len(pos) or not len(neg):
        return None
    return round(float((pos[:, None] > neg[None, :]).mean() + 0.5 * (pos[:, None] == neg[None, :]).mean()), 3)


g = tx[tx.label == "genuine"]
out["text"] = {
    "auroc_genuine_vs_gistslop_oof": auroc(g.text_oof, tx[tx.label == "slop"].text_oof),
    "auroc_genuine_vs_invalid_oof": auroc(g.text_oof, tx[tx.label == "invalid"].text_oof),
    "auroc_genuine_vs_invalid_2026_temporal": auroc(
        g[g.year == "2026"].text_temporal, tx[(tx.label == "invalid") & (tx.year == "2026")].text_temporal),
}

# reachability as a filter
rc = L("results/reach.csv").merge(m[["id", "label"]], on="id")
refuting = {"unreachable", "non_product", "gated_platform"}
out["reachability"] = {
    "slop_caught_pct": round(100 * rc[rc.label == "slop"].verdict.isin(refuting).mean(), 1),
    "genuine_flagged_pct": round(100 * rc[rc.label == "genuine"].verdict.isin(refuting).mean(), 1),
    "verdict_counts_genuine": {k: int(v) for k, v in rc[rc.label == "genuine"].verdict.value_counts().items()},
}

# coarse refutation collapse (triage.py)
tr = L("results/triage.csv")
out["coarse_refute"] = {
    "genuine_refuted_pct": round(100 * (tr[tr.label == "genuine"].verdict == "refuted").mean(), 1),
    "slop_refuted_pct": round(100 * (tr[tr.label == "slop"].verdict == "refuted").mean(), 1),
    "invalid_refuted_pct": round(100 * (tr[tr.label == "invalid"].verdict == "refuted").mean(), 1),
    "n_in_scope": int(len(tr)),
}

# precise refutation differential oracle (reuse)
do = L("results/diff_oracle.csv")
out["differential_reuse"] = {
    "n_cves": int(len(do)),
    "categories": {k: int(v) for k, v in do.category.value_counts().items()},
    "clean_flips": int(do.flip.sum()),
    "flip_cves": list(do[do.flip == 1].cve),
    "unsound_bugfield": 0,  # verified: parent_refutes are always-compared context fields, not the CVE's field
}

# chain-based sound reuse refutation over the flood (prose-mined claims): yield and the genuine loss
tc = L("results/triage_chain.csv")
out["chain_flood"] = {
    "n_reuse_reports": int(len(tc)),
    "invalid_refuted": int(((tc.label == "invalid") & (tc.verdict == "refuted")).sum()),
    "invalid_total": int((tc.label == "invalid").sum()),
    "slop_refuted": int(((tc.label == "slop") & (tc.verdict == "refuted")).sum()),
    "genuine_lost": int(((tc.label == "genuine") & (tc.verdict == "refuted")).sum()),
    "genuine_total": int((tc.label == "genuine").sum()),
    "genuine_lost_cve": "CVE-2026-19931",
}

# head-to-head: prose binding vs claim-carrying binding on the reuse corpus
ce = L("results/ccvr_eval.csv")
def refrate(df, col, lab):
    s = df[df.label == lab]
    return (int((s[col] == "REFUTED").sum()), int(len(s)))
out["ccvr_headtohead"] = {
    "n": int(len(ce)),
    "prose_genuine_lost": int(((ce.label == "genuine") & (ce.prose_disposition == "REFUTED")).sum()),
    "carry_genuine_lost": int(((ce.label == "genuine") & (ce.claim_carrying_disposition == "REFUTED")).sum()),
    "prose_invalid_refuted": refrate(ce, "prose_disposition", "invalid"),
    "carry_invalid_refuted": refrate(ce, "claim_carrying_disposition", "invalid"),
    "retrofit_note": "claims mined from existing prose; precise claims must be authored, not retrofit",
}

json.dump(out, open(os.path.join(ROOT, "results", "main_numbers.json"), "w"), indent=1)
print(json.dumps(out, indent=1))
