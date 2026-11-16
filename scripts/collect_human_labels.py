"""Merge every filled-in blind review file into data/interim/human_labels.csv, which scripts.finalize_dataset applies as an override.
    python -m scripts.collect_human_labels
"""
import glob
import pandas as pd
files = sorted(glob.glob("data/interim/*blind_review.csv") + glob.glob("data/interim/human_review_sample_blind.csv"))
parts = []
for f in files:
    d = pd.read_csv(f, keep_default_na=False)
    d["reviewer_label"] = d.reviewer_label.str.strip().str.lower()
    d = d[d.reviewer_label.isin(["scam", "legitimate", "unsure"])]
    if len(d): parts.append(d[["message_id", "reviewer_label"] + [c for c in ("reviewer_category",) if c in d.columns]].assign(source_file=f))
if not parts: raise SystemExit("no filled reviewer_label values found")
h = pd.concat(parts).drop_duplicates("message_id", keep="last")
h.drop(columns="source_file").to_csv("data/interim/human_labels.csv", index=False)
print(len(h), "human labels collected ->", "data/interim/human_labels.csv", h.reviewer_label.value_counts().to_dict(), "\nnow run: python -m scripts.finalize_dataset")
