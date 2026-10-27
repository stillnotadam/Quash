"""Soundness check: functions the test suite executes (via the public API or the tool) must be statically reachable."""
import json, os, sys, collections
r = json.load(open(sys.argv[1]))
N = r['nodes']
key = lambda t: (N[t]['file'], N[t]['name'])
alld = {key(t) for t in N}
cov = {tuple(x.split(':', 1)) for x in r['covered_funcs']} & alld
for mode in ('reach_direct', 'reach_typed', 'reach_coarse'):
    s = {key(t) for t in r[mode]}
    print(f"{mode:13s} reachable={len(s):5d}/{len(alld)}  covered-but-unreachable={len(cov - s):4d} ({100*len(cov-s)/len(cov):.1f}% of {len(cov)} covered)")
miss = sorted(cov - {key(t) for t in r['reach_typed']})
print(miss[:40])
