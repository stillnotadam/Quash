"""Text-only triage baseline (stand-in for the RoBERTa classifier of arXiv 2511.18608): word 1-2 gram TF-IDF with
L2-regularized logistic regression, implemented in numpy so it runs without extra packages.

Label: valid (genuine CVE or resolved) = 1, invalid (not-applicable, informative, spam, duplicate, slop) = 0.
Outputs out-of-fold scores for every natural report (10-fold stratified CV), temporal-split scores (train before
2025-07-01, test after), and scores for any extra report set (synthetic) from a model trained on all natural data.
"""
import json, os, re, sys
from collections import Counter
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOK = re.compile(r"[a-z_][a-z0-9_]{1,30}")


def tokens(t):
    w = TOK.findall((t or "").lower())
    return w + [a + " " + b for a, b in zip(w, w[1:])]


class Tfidf:
    def __init__(self, min_df=3, max_feat=30000):
        self.min_df, self.max_feat = min_df, max_feat

    def fit(self, docs):
        df = Counter()
        for d in docs:
            df.update(set(tokens(d)))
        items = [(t, c) for t, c in df.items() if c >= self.min_df]
        items.sort(key=lambda x: -x[1])
        items = items[:self.max_feat]
        self.vocab = {t: i for i, (t, _) in enumerate(items)}
        n = len(docs)
        self.idf = np.array([np.log((1 + n) / (1 + c)) + 1 for _, c in items], dtype=np.float32)
        return self

    def transform(self, docs):
        X = np.zeros((len(docs), len(self.vocab)), dtype=np.float32)
        for i, d in enumerate(docs):
            for t, c in Counter(tokens(d)).items():
                j = self.vocab.get(t)
                if j is not None:
                    X[i, j] = 1 + np.log(c)
        X *= self.idf
        X /= np.maximum(np.linalg.norm(X, axis=1, keepdims=True), 1e-9)
        return X


def fit_lr(X, y, lam=1e-3, iters=300, lr=0.5, balance=True):
    n, d = X.shape
    w, b = np.zeros(d, dtype=np.float32), 0.0
    sw = np.where(y == 1, n / (2 * y.sum()), n / (2 * (n - y.sum()))) if balance else np.ones(n)
    for _ in range(iters):
        p = 1 / (1 + np.exp(-(X @ w + b)))
        g = (p - y) * sw
        w -= lr * (X.T @ g / n + lam * w)
        b -= lr * g.mean()
    return w, b


def predict(X, wb):
    w, b = wb
    return 1 / (1 + np.exp(-(X @ w + b)))


def load_bodies(ids, d):
    out = []
    for i in ids:
        j = json.load(open(os.path.join(d, f"{i}.json"), encoding="utf-8"))
        out.append((j.get("title") or "") + "\n" + (j.get("vulnerability_information") or ""))
    return out


def main():
    m = pd.read_csv(os.path.join(ROOT, "data", "master.csv"), dtype={"id": str})
    docs = load_bodies(m.id, os.path.join(ROOT, "data", "h1"))
    y = m.label.isin(["genuine", "resolved"]).astype(np.float32).values
    rng = np.random.default_rng(0)
    folds = np.zeros(len(y), dtype=int)
    for cls in (0, 1):
        idx = np.where(y == cls)[0]
        rng.shuffle(idx)
        folds[idx] = np.arange(len(idx)) % 10
    oof = np.zeros(len(y))
    for k in range(10):
        tr, te = folds != k, folds == k
        vec = Tfidf().fit([docs[i] for i in np.where(tr)[0]])
        wb = fit_lr(vec.transform([docs[i] for i in np.where(tr)[0]]), y[tr])
        oof[te] = predict(vec.transform([docs[i] for i in np.where(te)[0]]), wb)
    m["text_oof"] = oof
    t = pd.to_datetime(m.created, utc=True) < pd.Timestamp("2025-07-01", tz="UTC")
    vec = Tfidf().fit([docs[i] for i in np.where(t)[0]])
    wb = fit_lr(vec.transform([docs[i] for i in np.where(t)[0]]), y[t.values])
    m["text_temporal"] = np.where(~t, predict(vec.transform(docs), wb), np.nan)
    m[["id", "text_oof", "text_temporal"]].to_csv(os.path.join(ROOT, "results", "text_scores.csv"), index=False)
    # full model for extra sets
    vec = Tfidf().fit(docs)
    X = vec.transform(docs)
    wb = fit_lr(X, y)
    np.save(os.path.join(ROOT, "results", "text_model_w.npy"), wb[0])
    top = np.argsort(wb[0])
    inv = {i: t for t, i in vec.vocab.items()}
    print("most invalid-indicative:", [inv[i] for i in top[:25]])
    print("most valid-indicative:", [inv[i] for i in top[-25:]])
    for extra in sys.argv[1:]:
        ids = [f[:-5] for f in sorted(os.listdir(extra)) if f.endswith(".json")]
        s = predict(vec.transform(load_bodies(ids, extra)), wb)
        pd.DataFrame({"id": ids, "text_full": s}).to_csv(os.path.join(ROOT, "results", "text_scores_" + os.path.basename(extra.rstrip("/\\")) + ".csv"), index=False)


if __name__ == "__main__":
    main()
