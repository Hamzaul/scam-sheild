"""Apply the final adjudication (label policy v2) to data/interim/merged_dataset.csv and write the deliverables.

Run from the project root (after scripts/build_dataset.py):
    python -m scripts.finalize_dataset

Outputs (data/processed/):
  final_dataset.csv                   every message with final label, scam_category, scam_group, confidence, method, reason
  train.csv / validation.csv / test.csv            main leakage-safe splits (test = real messages only, mostly English)
  test_hindi.csv / test_hinglish.csv  language test sets, held out from train/validation/test (labels await independent human review)
  heldout_benchmark_candidates.csv    the 45 curated benchmark messages (and any near-duplicates), held out
  review_remaining.csv                messages that stay in review
Also: data/interim/test_*_blind_review.csv (+ keys) for independent human labelling, docs/final_audit_report.md
Human labels: put message_id,reviewer_label[,reviewer_category] in data/interim/human_labels.csv and re-run - they override the automatic label.
"""
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from .Adjudicate import Adjudicate_frame, POLICY_VERSION, SPAM_CATEGORIES

SEED = 42
TEST_OK_ORIGINS = {"real", "hand_written"}            # only real / hand-written messages may enter the main test split
RESERVED_SOURCES = {"benchmark_ground_truth"}
LANG_TEST_SOURCE = "indian_scam_synthetic"            # Dataset D: never used to design or tune any rule -> unseen by the rules
OUT_COLS = ["message_id", "message", "language", "script", "language_detected", "final_label", "scam_category", "scam_group",
            "final_confidence", "final_method", "final_reason", "final_signals", "origin_type", "source", "source_quality",
            "source_id", "original_label", "source_kind", "pre_adjudication_label", "language_status", "template_id", "difficulty", "label_policy"]
HUMAN_PATH = "data/interim/human_labels.csv"


def apply_human_labels(d, path=HUMAN_PATH):
    """Independent human labels override the automatic decision. 'unsure' sends the message back to review."""
    p = Path(path)
    if not p.exists(): return d, 0
    h = pd.read_csv(p, keep_default_na=False)
    h["reviewer_label"] = h.reviewer_label.str.strip().str.lower()
    h = h[h.reviewer_label.isin(["scam", "legitimate", "unsure"])].drop_duplicates("message_id", keep="last")
    if "reviewer_category" not in h.columns: h["reviewer_category"] = ""
    d = d.copy(); m = h.set_index("message_id"); idx = d.index[d.message_id.isin(m.index)]
    for i in idx:
        lab, cat = m.at[d.at[i, "message_id"], "reviewer_label"], m.at[d.at[i, "message_id"], "reviewer_category"]
        d.at[i, "final_label"] = "review" if lab == "unsure" else lab
        d.at[i, "final_method"], d.at[i, "final_confidence"] = "human_review", ("low" if lab == "unsure" else "high")
        d.at[i, "final_reason"] = "independent human reviewer: " + lab
        if lab == "scam":
            keep = d.at[i, "scam_category"] not in ("none", "unassigned")
            d.at[i, "scam_category"] = cat or (d.at[i, "scam_category"] if keep else "OTHER_FRAUD")
        else:
            d.at[i, "scam_category"] = "none" if lab == "legitimate" else "unassigned"
    s = d.final_label == "scam"
    d.loc[s, "scam_group"] = d.loc[s, "scam_category"].map(lambda c: "spam" if c in SPAM_CATEGORIES else "fraud")
    d.loc[d.final_label == "legitimate", "scam_group"] = "none"
    d.loc[d.final_label == "review", "scam_group"] = "unassigned"
    return d, len(idx)


def grouped_split(sub, assign, mapper, n):
    f = StratifiedGroupKFold(n_splits=n, shuffle=True, random_state=SEED)
    for k, (_, idx) in enumerate(f.split(sub, (sub.final_label == "scam").astype(int), sub._grp)):
        assign[sub.index[idx]] = mapper(k)


def blind_review_files(part, name):
    part[["message_id", "message", "language", "script"]].assign(reviewer_label="", reviewer_category="", reviewer_notes="") \
        .to_csv(f"data/interim/{name}_blind_review.csv", index=False)
    part[["message_id", "final_label", "scam_category", "scam_group", "final_method", "final_confidence", "source", "origin_type"]] \
        .rename(columns={"final_label": "claude_label"}).to_csv(f"data/interim/{name}_key.csv", index=False)


def main():
    d = pd.read_csv("data/interim/merged_dataset.csv", keep_default_na=False)
    a = Adjudicate_frame(d)
    d = pd.concat([d.rename(columns={"label": "pre_adjudication_label"}), a], axis=1)
    d["scam_category"] = d.final_category
    d["label_policy"] = POLICY_VERSION
    d, n_human = apply_human_labels(d)
    if n_human: print(f"human labels applied: {n_human}")
    d["_grp"] = d.template_id.str.replace(r"^[A-Za-z_]+", "", regex=True).astype(int)
    d[OUT_COLS].to_csv("data/processed/final_dataset.csv", index=False)

    rv = d[d.final_label == "review"].copy()
    rv["priority"] = np.select([rv.final_method == "manual_read", rv.final_method == "rule_conflict", rv.final_method == "family_review"], [1, 2, 4], 3)
    rv = rv.sort_values(["priority", "source"])[["message_id", "message", "source", "language", "script", "final_method", "final_reason", "final_signals",
                                                  "original_label", "pre_adjudication_label", "priority"]]
    for c in ["reviewer_label", "reviewer_category", "reviewer_notes"]: rv[c] = ""
    rv.to_csv("data/processed/review_remaining.csv", index=False)

    # ---------------- partitions. Everything is assigned at the level of near-duplicate GROUPS, so no group is ever split.
    reserved_groups = set(d[d.source.isin(RESERVED_SOURCES)]._grp)
    d[d._grp.isin(reserved_groups)][OUT_COLS].to_csv("data/processed/heldout_benchmark_candidates.csv", index=False)
    ok = d[d.final_label.isin(["scam", "legitimate"]) & ~d._grp.isin(reserved_groups)].reset_index(drop=True)
    part = pd.Series("", index=ok.index, dtype=object)

    # language test sets (from Dataset D only; resolved, non-low-confidence; whole groups)
    cand = ok[(ok.source == LANG_TEST_SOURCE) & (ok.final_confidence != "low")]
    part[cand[cand.language == "Hindi"].index] = "test_hindi"
    hg = cand[cand.language == "Hinglish"]
    tmp = pd.Series(index=hg.index, dtype=object)
    grouped_split(hg, tmp, lambda k: "test_hinglish" if k == 0 else "pool", 2)         # half of the D-Hinglish groups
    part[tmp[tmp == "test_hinglish"].index] = "test_hinglish"
    lang_groups = set(ok[part.isin(["test_hindi", "test_hinglish"])]._grp)
    part[(part == "") & ok._grp.isin(lang_groups)] = "excluded_shares_group_with_language_test"   # never leak a near-duplicate

    rest = ok[part == ""]
    grp_ok = rest.groupby("_grp").apply(lambda g: set(g.origin_type) <= TEST_OK_ORIGINS and not (g.final_confidence == "low").any(), include_groups=False)
    test_ok = rest._grp.map(grp_ok)
    tmp = pd.Series(index=rest.index, dtype=object)
    grouped_split(rest[test_ok], tmp, lambda k: "train" if k < 14 else ("validation" if k < 17 else "test"), 20)
    grouped_split(rest[~test_ok], tmp, lambda k: "validation" if k == 0 else "train", 7)
    part[rest.index] = tmp
    for name in ["train", "validation", "test", "test_hindi", "test_hinglish"]:
        x = ok[part == name]
        lang = name.startswith("test_h")
        x = x.assign(label_status="awaiting_independent_review") if lang else x
        x[OUT_COLS + (["label_status"] if lang else [])].to_csv(f"data/processed/{name}.csv", index=False)
        print(f"{name:13s} n={len(x):6d} scam%={100*(x.final_label=='scam').mean() if len(x) else 0:5.1f}  {x.language.value_counts().to_dict()}")
    for name in ["test_hindi", "test_hinglish"]:
        if (part == name).any(): blind_review_files(ok[part == name], name)

    names = ["train", "validation", "test", "test_hindi", "test_hinglish"]
    G = [set(ok[part == n]._grp) for n in names]
    for i in range(len(G)):
        for j in range(i + 1, len(G)):
            assert not (G[i] & G[j]), f"template leakage between {names[i]} and {names[j]}"
    assert not (set(ok[part.isin(names)]._grp) & reserved_groups), "benchmark leaked"
    print("leakage check passed: no near-duplicate group shared between train / validation / test / test_hindi / test_hinglish / benchmark")

    for lang, n in [("Hindi", (part == "test_hindi").sum()), ("Hinglish", (part == "test_hinglish").sum())]:
        if n < 300:
            print(f"WARNING: the {lang} test set has only {n} messages (target >= 300 per class) and its labels are NOT yet independently reviewed; "
                  f"report wide confidence intervals and replace it with a human-verified real-world set (docs/evaluation_protocol.md).")

    # ---------------- audit report
    usable = d[d.final_label != "review"]
    sc = d[d.final_label == "scam"]
    rep = ["# Final audit report (auto-generated by scripts/finalize_dataset.py)\n", f"Label policy: **{POLICY_VERSION}** (promotion / bulk ads / spam = scam; genuine notifications, OTPs, delivery alerts, personal = legitimate; uncertain = review).\n",
           f"Rows: **{len(d)}**. scam **{(d.final_label=='scam').sum()}**, legitimate **{(d.final_label=='legitimate').sum()}**, review **{(d.final_label=='review').sum()}**.\n",
           "## Scam group (spam vs fraud) x language\n", pd.crosstab(sc.scam_group, sc.language, margins=True).to_markdown(), "\n",
           "## scam_category x scam_group\n", pd.crosstab(sc.scam_category, sc.scam_group, margins=True).to_markdown(), "\n",
           "## Origin type x final label\n", pd.crosstab(d.origin_type, d.final_label, margins=True).to_markdown(), "\n",
           "## Language x script\n", pd.crosstab(d.language, d.script, margins=True).to_markdown(), "\n",
           "## Source class -> final label\n", pd.crosstab(d.source_kind, d.final_label, margins=True).to_markdown(), "\n",
           "## Decision method x final label\n", pd.crosstab(d.final_method, d.final_label, margins=True).to_markdown(), "\n",
           "## Confidence x final label\n", pd.crosstab(d.final_confidence, d.final_label, margins=True).to_markdown(), "\n",
           "## Source x final label\n", pd.crosstab(d.source, d.final_label, margins=True).to_markdown(), "\n",
           "## Language x final label (resolved only)\n", pd.crosstab(usable.language, usable.final_label, margins=True).to_markdown(), "\n",
           "## Partition x language x label\n", pd.crosstab([ok.language, ok.final_label], part.rename("partition")).to_markdown(), "\n"]
    Path("docs/final_audit_report.md").write_text("\n".join(rep), encoding="utf-8")
    print(d.final_label.value_counts().to_dict(), "| scam groups:", sc.scam_group.value_counts().to_dict())


if __name__ == "__main__":
    main()
