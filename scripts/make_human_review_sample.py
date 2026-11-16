"""Draw a stratified sample for INDEPENDENT human verification of the final labels.

Strata are language x label-group x origin, so no group can be absorbed into another one (the old script let a catch-all
'family_read' stratum swallow every Hindi scam). The 45-message benchmark is always its own stratum. Messages that sit in the
language test sets are excluded here: they have their own review files (data/interim/test_hindi_blind_review.csv, ...).

Writes:  data/interim/human_review_sample_blind.csv  (message_id, message, language, script, reviewer_label, reviewer_category, reviewer_notes)
         data/interim/human_review_sample_key.csv    (claude_label, stratum, stratum_size, weight, ...)  - keep private
Reviewer labels: scam | legitimate | unsure.        Then:  python -m scripts.score_human_review
"""
import pandas as pd

SEED = 42
ORIGIN_GROUP = {"real": "real", "hand_written": "real", "synthetic_llm": "synthetic", "templated_synthetic": "templated",
                "machine_translated": "translated", "curated_benchmark": "benchmark"}
LABEL_GROUP = {"legitimate": "legit"}


def build_strata(d):
    """one stratum per row; returns a Series. Benchmark first, review pool by language, everything else language x label-group x origin."""
    lg = d.final_label.map(LABEL_GROUP).where(d.final_label != "scam", "scam_" + d.scam_group.astype(str))
    og = d.origin_type.map(ORIGIN_GROUP)
    s = d.language + "_" + lg + "__" + og
    s = s.where(d.final_label != "review", "review_" + d.language)
    return s.where(d.source != "benchmark_ground_truth", "benchmark_all")


def allocation(size):
    """sample size per stratum: everything for small strata (<=40), 40 for mid-size, 80 for large (>=1000)"""
    return size if size <= 40 else (40 if size < 1000 else 80)


def draw_sample(d, exclude_ids=()):
    d = d[~d.message_id.isin(set(exclude_ids))].copy()
    d["stratum"] = build_strata(d)
    parts = []
    for name, pool in d.groupby("stratum"):
        take = pool if len(pool) <= allocation(len(pool)) else pool.sample(allocation(len(pool)), random_state=SEED)
        parts.append(take.assign(stratum_size=len(pool), weight=len(pool) / len(take)))
    s = pd.concat(parts)
    # guard: no stratum may be silently lost or absorbed
    for name, pool in d.groupby("stratum"):
        assert name in set(s.stratum), f"stratum {name} missing from sample"
    hs = d[(d.language == "Hindi") & (d.final_label == "scam") & (d.stratum != "benchmark_all")]      # benchmark is its own stratum by design
    if len(hs):
        got = s[(s.language == "Hindi") & (s.final_label == "scam") & (s.stratum != "benchmark_all")]
        assert len(got) > 0 and got.stratum.str.startswith("Hindi_scam_").all(), "Hindi scam messages were absorbed into another stratum"
    return s.sample(frac=1, random_state=SEED).reset_index(drop=True)


def main():
    d = pd.read_csv("data/processed/final_dataset.csv", keep_default_na=False)
    lang_test = set()
    for n in ("test_hindi", "test_hinglish"):
        try: lang_test |= set(pd.read_csv(f"data/processed/{n}.csv", keep_default_na=False).message_id)
        except FileNotFoundError: pass
    s = draw_sample(d, exclude_ids=lang_test)
    s[["message_id", "message", "language", "script"]].assign(reviewer_label="", reviewer_category="", reviewer_notes="") \
        .to_csv("data/interim/human_review_sample_blind.csv", index=False)
    s[["message_id", "final_label", "scam_category", "scam_group", "final_method", "final_confidence", "origin_type", "source", "stratum", "stratum_size", "weight"]] \
        .rename(columns={"final_label": "claude_label"}).to_csv("data/interim/human_review_sample_key.csv", index=False)
    print(len(s), "rows in", s.stratum.nunique(), "strata;  Hindi-scam strata:",
          s[(s.language == "Hindi") & (s.final_label == "scam")].stratum.value_counts().to_dict())


if __name__ == "__main__":
    main()
