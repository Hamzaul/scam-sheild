"""Tests for the human-review sampler (strata) and scorer (population weighting, kappas)."""
import os, unittest
import numpy as np, pandas as pd
from scripts.make_human_review_sample import build_strata, draw_sample, allocation
from scripts.score_human_review import prepare, report, weighted_agreement, weighted_confusion


def toy_dataset():
    rows = []
    def add(n, language, label, group, origin, source="s", method="rule_scam"):
        for i in range(n):
            rows.append(dict(message_id=f"{language}{label}{group}{origin}{len(rows)}", message="m", language=language, script="x", final_label=label,
                             scam_group=group, origin_type=origin, source=source, final_method=method, scam_category="X", final_confidence="high"))
    add(3000, "English", "legitimate", "none", "real"); add(500, "English", "scam", "spam", "real"); add(200, "English", "scam", "fraud", "real")
    add(120, "Hindi", "scam", "fraud", "synthetic_llm", method="family_read")      # the old bug: absorbed by a family_read catch-all
    add(30, "Hindi", "legitimate", "none", "machine_translated"); add(7, "Hindi", "scam", "fraud", "curated_benchmark", source="benchmark_ground_truth")
    add(80, "Hinglish", "scam", "fraud", "templated_synthetic", method="family_read"); add(50, "English", "review", "unassigned", "real", method="unresolved")
    return pd.DataFrame(rows)


class SamplerStrata(unittest.TestCase):
    def test_hindi_scam_is_never_absorbed_by_family_read(self):
        d = toy_dataset(); s = draw_sample(d)
        hs = s[(s.language == "Hindi") & (s.final_label == "scam") & (s.source != "benchmark_ground_truth")]
        self.assertGreater(len(hs), 0)
        self.assertTrue(hs.stratum.str.startswith("Hindi_scam_fraud__").all())
        self.assertNotIn("family_read", set(s.stratum))

    def test_benchmark_is_its_own_stratum(self):
        s = draw_sample(toy_dataset())
        b = s[s.source == "benchmark_ground_truth"]
        self.assertEqual(set(b.stratum), {"benchmark_all"}); self.assertEqual(len(b), 7)
        self.assertTrue((b.weight == 1).all())

    def test_spam_and_fraud_scams_are_separate_strata(self):
        st = set(draw_sample(toy_dataset()).stratum)
        self.assertIn("English_scam_spam__real", st); self.assertIn("English_scam_fraud__real", st)

    def test_weights_sum_to_population_and_every_stratum_is_present(self):
        d = toy_dataset(); s = draw_sample(d)
        self.assertAlmostEqual(s.weight.sum(), len(d), places=6)
        self.assertEqual(set(build_strata(d)), set(s.stratum))

    def test_language_test_rows_can_be_excluded(self):
        d = toy_dataset(); ids = d[d.language == "Hinglish"].message_id
        self.assertFalse(draw_sample(d, exclude_ids=ids).language.eq("Hinglish").any())

    def test_allocation(self):
        self.assertEqual((allocation(10), allocation(40), allocation(500), allocation(5000)), (10, 40, 40, 80))

    @unittest.skipUnless(os.path.exists("data/processed/final_dataset.csv"), "final dataset not built")
    def test_real_dataset_keeps_hindi_scam_strata(self):
        d = pd.read_csv("data/processed/final_dataset.csv", keep_default_na=False)
        d = d[~d.message_id.isin(set(pd.read_csv("data/processed/test_hindi.csv", keep_default_na=False).message_id))]
        s = draw_sample(d)
        self.assertTrue(any(x.startswith("Hindi_scam_") for x in s.stratum))


def scored(rows):
    """rows: (stratum, stratum_size, n_sampled, n_agree, claude_label)"""
    out = []
    for st, size, n, agree, lab in rows:
        other = "legitimate" if lab == "scam" else "scam"
        for i in range(n):
            out.append(dict(message_id=f"{st}{i}", claude_label=lab, reviewer_label=lab if i < agree else other, stratum=st, stratum_size=size, weight=size / n))
    return pd.DataFrame(out)


class Scorer(unittest.TestCase):
    def test_weighted_agreement_is_not_the_sample_agreement(self):
        # big stratum (1000 msgs) agrees 100% on 10 sampled; tiny stratum (10 msgs) agrees 0% on 10 sampled
        df = scored([("big", 1000, 10, 10, "legitimate"), ("tiny", 10, 10, 0, "scam")])
        self.assertAlmostEqual((df.claude_label == df.reviewer_label).mean(), 0.5)           # unweighted sample agreement
        self.assertAlmostEqual(weighted_agreement(df), 1000 / 1010, places=6)                 # population-weighted
        self.assertAlmostEqual(weighted_confusion(df).values.sum(), 1010, places=6)

    def test_report_gives_two_separate_kappas_and_a_warning(self):
        df = scored([("big", 1000, 40, 38, "legitimate"), ("tiny", 20, 20, 10, "scam"), ("mid", 300, 30, 27, "scam")])
        text, m = report(df.assign(reviewer_notes=""))
        self.assertIn("ordinary Cohen's kappa", text); self.assertIn("weighted Cohen's kappa", text)
        self.assertIn("NOT the dataset", text)
        self.assertNotAlmostEqual(m["kappa_sample"], m["kappa_weighted"], places=3)
        self.assertNotAlmostEqual(m["agreement_sample"], m["agreement_weighted"], places=3)
        self.assertLessEqual(m["ci"][0], m["agreement_weighted"]); self.assertGreaterEqual(m["ci"][1], m["agreement_weighted"])

    def test_unsure_is_excluded_and_review_pool_reported_separately(self):
        df = scored([("a", 100, 10, 10, "scam")])
        extra = pd.DataFrame([dict(message_id="u", claude_label="legitimate", reviewer_label="unsure", stratum="a", stratum_size=100, weight=10.0),
                              dict(message_id="r", claude_label="review", reviewer_label="scam", stratum="review_English", stratum_size=50, weight=5.0)])
        text, m = report(pd.concat([df, extra]))
        self.assertIn("unsure: 1", text); self.assertIn("left in REVIEW", text)
        self.assertAlmostEqual(m["agreement_weighted"], 1.0)

    def test_prepare_defaults_for_census_files(self):          # language test sets: no weights/strata in the key
        key = pd.DataFrame({"message_id": ["1", "2"], "claude_label": ["scam", "legitimate"]})
        blind = pd.DataFrame({"message_id": ["1", "2"], "reviewer_label": [" Scam", "scam"]})
        m = prepare(blind, key)
        self.assertEqual(list(m.weight), [1.0, 1.0]); self.assertEqual(list(m.reviewer_label), ["scam", "scam"])


if __name__ == "__main__":
    unittest.main()
