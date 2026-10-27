"""Fill paper_template.html with numbers from main_numbers.json and base64-embedded figures -> paper/paper.html."""
import base64, json, os, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "paper")
num = json.load(open(os.path.join(ROOT, "results", "main_numbers.json")))


def img(name):
    b = base64.b64encode(open(os.path.join(P, "fig", name), "rb").read()).decode()
    return f'<img alt="{name}" src="data:image/png;base64,{b}">'


reach_ceiling = "about 80%"  # 2602/3222 defined functions reachable in 8.23.0 (from cg)
repl = {
    "DATE": datetime.date.today().isoformat(),
    "N_TOTAL": num["corpus_total"], "N_GEN": num["corpus"]["genuine"], "N_SLOP": num["corpus"]["slop"],
    "N_RES": num["corpus"]["resolved"], "N_INV": num["corpus"]["invalid"],
    "EX_SLOP_PASS": num["existence"]["slop_passes_grounding_pct"],
    "EX_GEN_FLAG": num["existence"]["genuine_flagged_ungrounded_pct"],
    "TX_GIST": num["text"]["auroc_genuine_vs_gistslop_oof"],
    "TX_INVALL": num["text"]["auroc_genuine_vs_invalid_oof"],
    "TX_2026": num["text"]["auroc_genuine_vs_invalid_2026_temporal"],
    "REACH_SLOP": num["reachability"]["slop_caught_pct"], "REACH_GEN": num["reachability"]["genuine_flagged_pct"],
    "REACH_CEIL": reach_ceiling,
    "COARSE_GEN": num["coarse_refute"]["genuine_refuted_pct"], "COARSE_SLOP": num["coarse_refute"]["slop_refuted_pct"],
    "DIFF_FLIP": num["differential_reuse"]["clean_flips"],
    "CHAIN_N": num["chain_flood"]["n_reuse_reports"],
    "CHAIN_INV_REF": num["chain_flood"]["invalid_refuted"], "CHAIN_INV_TOT": num["chain_flood"]["invalid_total"],
    "CHAIN_GLOST": num["chain_flood"]["genuine_lost"], "CHAIN_GTOT": num["chain_flood"]["genuine_total"],
    "CC_N": num["ccvr_headtohead"]["n"], "CC_PROSE_INV": num["ccvr_headtohead"]["prose_invalid_refuted"][0],
    "CC_PROSE_GLOST": num["ccvr_headtohead"]["prose_genuine_lost"], "CC_CARRY_GLOST": num["ccvr_headtohead"]["carry_genuine_lost"],
    "FIG_CORPUS": img("corpus_year.png"), "FIG_TEXT": img("text_auroc.png"),
    "FIG_COLLAPSE": img("collapse.png"), "FIG_DIFF": img("diff_oracle.png"),
}
html = open(os.path.join(P, "paper_template.html"), encoding="utf-8").read()
for k, v in repl.items():
    html = html.replace("{{" + k + "}}", str(v))
open(os.path.join(P, "paper.html"), "w", encoding="utf-8").write(html)
left = [t for t in __import__("re").findall(r"\{\{(\w+)\}\}", html)]
print("wrote paper/paper.html", len(html), "bytes; unfilled tokens:", set(left))
