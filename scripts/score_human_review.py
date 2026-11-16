"""Compare an independent human reviewer with the final labels.

    python -m scripts.score_human_review                       # general sample (stratified, weighted)
    python -m scripts.score_human_review --blind data/interim/test_hindi_blind_review.csv --key data/interim/test_hindi_key.csv   # language test set (census, weight 1)

IMPORTANT - what the numbers mean
  * sample (unweighted) agreement describes the SAMPLE only. Strata were sampled at very different rates (rare Hindi/Hinglish strata are
    over-sampled), so it is NOT the accuracy of the dataset.
  * population-weighted agreement re-weights each reviewed message by (stratum size / messages sampled in that stratum) and is the estimate of
    label agreement over the WHOLE reviewed population. Its bootstrap interval resamples within strata.
  * Cohen's kappa is reported twice, separately: ordinary (sample) kappa and population-weighted kappa.
  * 'unsure' answers are excluded from agreement and reported; review-pool messages have no automatic label to compare and are reported separately.
"""
import argparse
import numpy as np, pandas as pd
from sklearn.metrics import cohen_kappa_score

LABELS = ["scam", "legitimate"]


def prepare(blind, key):
    m = key.merge(blind[["message_id", "reviewer_label"] + [c for c in ("reviewer_notes",) if c in blind.columns]], on="message_id")
    if "weight" not in m.columns: m["weight"] = 1.0
    if "stratum" not in m.columns: m["stratum"] = "all"
    if "stratum_size" not in m.columns: m["stratum_size"] = m.groupby("stratum").weight.transform("size")
    m["reviewer_label"] = m.reviewer_label.astype(str).str.strip().str.lower()
    return m[m.reviewer_label.isin(["scam", "legitimate", "unsure"])].copy()


def weighted_agreement(df):
    return float(np.average((df.claude_label == df.reviewer_label).astype(float), weights=df.weight))


def weighted_confusion(df):
    c = pd.DataFrame(0.0, index=LABELS, columns=LABELS)
    for (a, b), w in df.groupby(["claude_label", "reviewer_label"]).weight.sum().items():
        if a in LABELS and b in LABELS: c.loc[a, b] = w
    return c


def bootstrap_ci(df, reps=1000, seed=42):
    """stratified bootstrap of the population-weighted agreement: resample reviewed messages within each stratum"""
    rng = np.random.RandomState(seed); groups = [g for _, g in df.groupby("stratum")]; out = []
    for _ in range(reps):
        s = pd.concat([g.iloc[rng.randint(0, len(g), len(g))] for g in groups])
        # a bootstrap sample keeps each stratum's sampled size, so the original weights stay valid
        out.append(weighted_agreement(s))
    return float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))


def report(m):
    done = m[m.reviewer_label != "unsure"]
    dec = done[done.claude_label.isin(LABELS)].copy()
    lines = []
    lines.append(f"reviewed: {len(m)} | unsure: {(m.reviewer_label=='unsure').sum()} | comparable (scam/legitimate vs automatic label): {len(dec)}")
    if len(dec) == 0: return "\n".join(lines + ["no comparable rows yet"]), {}
    ag_s, ag_w = float((dec.claude_label == dec.reviewer_label).mean()), weighted_agreement(dec)
    k_s = cohen_kappa_score(dec.claude_label, dec.reviewer_label, labels=LABELS)
    k_w = cohen_kappa_score(dec.claude_label, dec.reviewer_label, labels=LABELS, sample_weight=dec.weight)
    lo, hi = bootstrap_ci(dec)
    lines += ["", "SAMPLE (unweighted) - describes the reviewed sample only, NOT the dataset:",
              f"  agreement {ag_s:.1%}   |   ordinary Cohen's kappa {k_s:.3f}",
              "POPULATION-WEIGHTED - estimate for the whole reviewed population:",
              f"  agreement {ag_w:.1%}  (95% bootstrap CI {lo:.1%} - {hi:.1%})   |   weighted Cohen's kappa {k_w:.3f}",
              "", "Confusion matrix, SAMPLE counts (rows = automatic label, columns = human):", pd.crosstab(dec.claude_label, dec.reviewer_label).reindex(index=LABELS, columns=LABELS, fill_value=0).to_string(),
              "", "Confusion matrix, POPULATION-WEIGHTED (estimated message counts):", weighted_confusion(dec).round(0).astype(int).to_string()]
    dec["disagree"] = (dec.claude_label != dec.reviewer_label).astype(int)
    g = dec.groupby("stratum").apply(lambda x: pd.Series({"reviewed": len(x), "disagree": int(x.disagree.sum()), "disagree_rate": round(x.disagree.mean(), 3),
                                                          "stratum_size": int(x.stratum_size.iloc[0]), "est_wrong_labels": round(x.disagree.mean() * x.stratum_size.iloc[0])}), include_groups=False)
    lines += ["", "Per stratum (est_wrong_labels = disagree_rate x stratum_size):", g.sort_values("est_wrong_labels", ascending=False).to_string(),
              "", f"Estimated wrong labels in the reviewed population: about {int(g.est_wrong_labels.sum())} of {int(g.stratum_size.sum())}"]
    rp = m[(m.reviewer_label != "unsure") & ~m.claude_label.isin(LABELS)]
    if len(rp):
        w = rp.groupby("reviewer_label").weight.sum(); lines += ["", "Messages the automatic process left in REVIEW, as judged by the human (population-weighted share):",
                                                                  (w / w.sum()).round(3).to_string()]
    return "\n".join(lines), {"agreement_sample": ag_s, "agreement_weighted": ag_w, "kappa_sample": k_s, "kappa_weighted": k_w, "ci": (lo, hi)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blind", default="data/interim/human_review_sample_blind.csv"); ap.add_argument("--key", default="data/interim/human_review_sample_key.csv")
    a = ap.parse_args()
    blind = pd.read_csv(a.blind, keep_default_na=False); key = pd.read_csv(a.key, keep_default_na=False)
    m = prepare(blind, key)
    if m.empty: raise SystemExit("no reviewer_label filled in yet (scam / legitimate / unsure)")
    print(report(m)[0])


if __name__ == "__main__":
    main()
