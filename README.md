# Proof-Carrying Triage

Artifact for the paper **"Proof-Carrying Triage: Refuting AI-Generated Vulnerability Reports with Certificates a
Maintainer Can Check."** Triaging grounded, AI-generated vulnerability reports by **refutation**: proving a report's
central claim impossible against the program and returning a machine-checkable certificate (an SMT unsat core over
GCC GIMPLE), validated by a differential fix-commit oracle. Study subject: curl.

The paper is in `paper/paper.pdf` (compile `paper/paper.tex`, or read `paper/paper.html`).

## Try it in 60 seconds
No curl build needed; the reference checker runs on committed GIMPLE for the example claims.
```
git clone https://github.com/stillnotadam/quash
cd quash
pip install -r requirements.txt
python code/ccvr_check.py paper/examples/slop_bounds_telnet.json       # REFUTED + "verified-unsat"
python code/ccvr_check.py paper/examples/slop_bounds_ws.json           # REFUTED + "verified-unsat"
python code/ccvr_check.py paper/examples/slop_reuse_host.json          # REFUTED + "verified-unsat"
python code/ccvr_check.py paper/examples/genuine_CVE-2026-19931.json   # ESCALATE (genuine preserved)
python code/ccvr_check.py paper/examples/genuine_bounds_CVE-2023-38545.json  # ESCALATE
```
Each REFUTED verdict prints a standalone SMT-LIB proof obligation and re-verifies it in a fresh solver
(`"independent_verification": "verified-unsat"`); the two genuine CVEs are escalated, not refuted. Write your own
claim by copying a file in `paper/examples/` (format: `paper/claim_schema.json`).

## Safety and scope
This repository is **defense only**. It contains no grounded-slop generator (none was built). It does **not**
redistribute raw HackerOne report bodies; it ships report **IDs and labels** plus fetch scripts, so anyone can
regenerate the inputs from the public sources. All study data is from already-public, already-disclosed reports;
nothing was submitted to any live program. The pipeline emits verdicts and certificates only and never synthesizes
an input, so it cannot be used as an exploit generator.

## Layout
- `code/` the pipeline (Python 3 with numpy, pandas, z3-solver; GCC and git in a Linux/WSL environment for builds).
- `results/` committed derived artifacts: every number in the paper is traceable to a file here (see the map below).
- `data/` report IDs, labels and derived metadata (`master.csv`), plus the public source lists (curl `vuln.json`,
  the maintainer slop gist, curl `releases.csv`) and fetch scripts. No raw report bodies.
- `paper/` the paper (`paper.tex`, `paper.html`), figures, the claim-carrying schema (`claim_schema.json`), and
  runnable example claims (`paper/examples/*.json`).

## Reproducing the numbers
`results/main_numbers.json` is the single source of truth; the build injects it into the paper, so prose and code
cannot drift. Two tiers:

- **Verify from committed artifacts (no heavy build):** every headline number is in `results/main_numbers.json` and
  the CSV it was computed from (both committed). Re-run `python code/maintable.py` to regenerate `main_numbers.json`
  from the committed CSVs and confirm the values.
- **Full rebuild from scratch (heavy, needs WSL + GCC):** `code/wsl_*.sh` build 41 curl releases, dump GIMPLE, and
  run the call-graph and reachability passes; the Python scripts then produce the CSVs. The reference checker
  `code/ccvr_check.py` runs on the committed GIMPLE-derived artifacts and example claims with no build.

Run the reference checker on a carried claim (emits an SMT certificate and re-verifies it independently):
```
python code/ccvr_check.py paper/examples/slop_bounds_telnet.json      # REFUTED + verified-unsat
python code/ccvr_check.py paper/examples/genuine_CVE-2026-19931.json  # ESCALATE (genuine preserved)
```

## Number-to-source map (every empirical claim in the paper)
| Paper claim | Value | Committed source | Script |
|---|---|---|---|
| Corpus size and labels | 684 total; 148 genuine, 49 slop, 472 invalid, 15 resolved | `results/main_numbers.json` (`corpus`), `data/master.csv` | `code/build_index.py` |
| Existence grounding: slop that passes | 53.1% | `results/existence_scoped.csv`, `main_numbers.json` (`existence`) | `code/exist_check.py`, `code/maintable.py` |
| Existence grounding: genuine wrongly flagged | 33.8% | `results/existence_scoped.csv`, `main_numbers.json` | `code/exist_check.py`, `code/maintable.py` |
| Text classifier AUROC (gist slop / all invalid / 2026 temporal) | 0.985 / 0.745 / 0.608 | `results/text_scores.csv`, `main_numbers.json` (`text`) | `code/textclf.py`, `code/maintable.py` |
| Reachability: slop caught / genuine flagged | 12.2% / 1.4% | `results/reach.csv`, `main_numbers.json` (`reachability`) | `code/reach_check.py`, `code/maintable.py` |
| Reachability ceiling (functions reachable) | ~82% | `results/cg/cg-8.23.0.json` | `code/callgraph.py` |
| Coarse refutation: genuine / slop refuted | 35.6% / 0% | `results/triage.csv`, `main_numbers.json` (`coarse_refute`) | `code/triage.py`, `code/maintable.py` |
| Differential oracle: clean flips and categories | 3 flips / 27; 3 clean, 21 out-of-model, 3 no-dump | `results/diff_oracle.csv`, `main_numbers.json` (`differential_reuse`) | `code/diff_oracle.py`, `code/reuse_cves.py` |
| Head-to-head: prose vs claim-carrying genuine lost | prose 1, claim-carrying 0 | `results/ccvr_eval.csv`, `main_numbers.json` (`ccvr_headtohead`) | `code/ccvr_eval.py`, `code/refute_chain.py` |
| Head-to-head: invalid refuted (prose) | 5 / 86 | `results/ccvr_eval.csv`, `results/triage_chain.csv` | `code/ccvr_eval.py`, `code/triage_chain.py` |
| Checker dispositions + SMT certificates | REFUTED/ESCALATE per example | `paper/examples/*.json` | `code/ccvr_check.py` (re-verifies `verified-unsat`) |

## License
Code: MIT (see `LICENSE` if present, otherwise MIT applies to `code/`). Paper and data: CC BY 4.0.

## Citation
Melhem, A. "Proof-Carrying Triage: Refuting AI-Generated Vulnerability Reports with Certificates a Maintainer Can
Check." 2026. (Add the arXiv or Zenodo DOI once posted.)
