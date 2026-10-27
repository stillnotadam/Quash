"""Generate the paper's figures as PNGs from the consolidated numbers and raw CSVs. Runs on Windows (matplotlib)."""
import json, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "paper", "fig")
os.makedirs(FIG, exist_ok=True)
num = json.load(open(os.path.join(ROOT, "results", "main_numbers.json")))
plt.rcParams.update({"font.size": 11, "figure.dpi": 140})
INK, ACC, BAD, GOOD = "#1a1a2e", "#3a6ea5", "#c1403d", "#2e7d5b"

# Fig 1: soundness (genuine preserved) per method; only precise refutation is fully sound. Reach annotated.
methods = [
    ("Existence\ngrounding", 100 - num["existence"]["genuine_flagged_ungrounded_pct"], "passes 53% slop"),
    ("Reachability", 100 - num["reachability"]["genuine_flagged_pct"], "catches 12% slop"),
    ("Coarse\nrefutation", 100 - num["coarse_refute"]["genuine_refuted_pct"], "catches 0% slop"),
    ("Precise\nrefutation\n(CRDS)", 100.0, "narrow but\ncertified"),
]
fig, ax = plt.subplots(figsize=(7.0, 4.1))
x = np.arange(len(methods))
preserved = [m[1] for m in methods]
cols = [BAD if p < 95 else GOOD for p in preserved]
bars = ax.bar(x, preserved, 0.55, color=cols)
ax.set_xticks(x)
ax.set_xticklabels([m[0] for m in methods])
ax.set_ylabel("genuine reports preserved (%)  =  soundness")
ax.set_title("Only precise refutation is sound on grounded reports")
ax.axhline(100, ls=":", c="#999", lw=0.8)
ax.set_ylim(0, 112)
for i, (m, p) in enumerate(zip(methods, preserved)):
    ax.text(i, p + 1.5, f"{p:.1f}%", ha="center", fontsize=10, fontweight="bold")
    ax.text(i, 6, m[2], ha="center", fontsize=8, color="#fff" if p > 20 else INK)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "collapse.png"))
plt.close(fig)

# Fig 2: text classifier AUROC degrades from gist-slop to grounded 2026
fig, ax = plt.subplots(figsize=(5.2, 3.6))
labels = ["vs gist slop\n(2024-25)", "vs invalid\n(all)", "vs invalid\n(2026 temporal)"]
vals = [num["text"]["auroc_genuine_vs_gistslop_oof"], num["text"]["auroc_genuine_vs_invalid_oof"],
        num["text"]["auroc_genuine_vs_invalid_2026_temporal"]]
cols = [GOOD, ACC, BAD]
ax.bar(labels, vals, color=cols)
ax.axhline(0.5, ls="--", c="#999", lw=1)
ax.set_ylim(0.45, 1.0)
ax.set_ylabel("AUROC (genuine vs invalid)")
ax.set_title("Text triage collapses toward chance on grounded 2026 reports")
for i, v in enumerate(vals):
    ax.text(i, v + 0.01, f"{v:.3f}", ha="center", fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "text_auroc.png"))
plt.close(fig)

# Fig 3: differential reuse oracle categories
fig, ax = plt.subplots(figsize=(5.6, 3.4))
cats = num["differential_reuse"]["categories"]
order = ["clean_flip", "out_of_model", "no_matcher_dump"]
names = {"clean_flip": "clean sound flip", "out_of_model": "out of model\n(flag/bitfield/struct)", "no_matcher_dump": "no analyzable\nmatcher build"}
vals = [cats.get(k, 0) for k in order]
cols = [GOOD, "#c98a2b", "#888"]
ax.barh([names[k] for k in order][::-1], vals[::-1], color=cols[::-1])
ax.set_xlabel("connection-reuse CVEs (n=27)")
ax.set_title("Differential fix-commit oracle: where precise refutation applies")
for i, v in enumerate(vals[::-1]):
    ax.text(v + 0.2, i, str(v), va="center", fontsize=10)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "diff_oracle.png"))
plt.close(fig)

# Fig 4: corpus over time (grounded era)
m = pd.read_csv(os.path.join(ROOT, "data", "master.csv"), dtype={"id": str})
m["year"] = m.created.str[:4]
piv = pd.crosstab(m.year, m.label)
fig, ax = plt.subplots(figsize=(6.4, 3.6))
bottom = np.zeros(len(piv))
for lab, c in [("genuine", GOOD), ("resolved", "#7bb59a"), ("slop", BAD), ("invalid", "#d0a0a0")]:
    if lab in piv:
        ax.bar(piv.index, piv[lab], bottom=bottom, label=lab, color=c)
        bottom += piv[lab].values
ax.set_ylabel("disclosed reports")
ax.set_title("curl HackerOne reports by year (the grounded-report era)")
ax.legend(fontsize=8, ncol=2)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "corpus_year.png"))
plt.close(fig)
print("figures written to", FIG, os.listdir(FIG))
