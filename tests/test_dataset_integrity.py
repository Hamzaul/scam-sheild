"""Release checks on the generated files (skipped if the pipeline has not been run).  Run: python -m unittest discover -s tests -t ."""
import os, re, unittest
import pandas as pd
from scripts.cleaning import is_placeholder
from scripts.Adjudicate import SPAM_CATEGORIES

P = "data/processed/"
NAMES = ["train", "validation", "test", "test_hindi", "test_hinglish"]
READY = all(os.path.exists(P + f) for f in ["final_dataset.csv", "train.csv", "validation.csv", "test.csv", "test_hindi.csv", "test_hinglish.csv", "heldout_benchmark_candidates.csv"])
rd = lambda f: pd.read_csv(P + f, keep_default_na=False)
norm = lambda t: re.sub(r"\s+", " ", re.sub(r"\d", "0", re.sub(r"[^a-z0-9\u0900-\u097f ]", " ", t.lower()))).strip()


@unittest.skipUnless(READY, "run build_dataset + finalize_dataset first")
class ReleaseChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = rd("final_dataset.csv"); cls.parts = {n: rd(n + ".csv") for n in NAMES}; cls.bench = rd("heldout_benchmark_candidates.csv")
        cls.grp = lambda s, d: set(d.template_id.str.replace(r"^[A-Za-z_]+", "", regex=True))

    def test_no_empty_or_placeholder_messages_anywhere(self):
        for name, d in {**self.parts, "final": self.f, "benchmark": self.bench}.items():
            self.assertEqual(int(d.message.map(is_placeholder).sum()), 0, name)

    def test_valid_labels_and_policy_version(self):
        self.assertTrue(set(self.f.final_label) <= {"scam", "legitimate", "review"}); self.assertEqual(set(self.f.label_policy), {"v2"})
        for n, d in self.parts.items(): self.assertTrue(set(d.final_label) <= {"scam", "legitimate"}, n)

    def test_scam_rows_have_category_and_consistent_group(self):
        s = self.f[self.f.final_label == "scam"]
        self.assertFalse(s.scam_category.isin(["none", "unassigned", ""]).any())
        self.assertTrue(((s.scam_group == "spam") == s.scam_category.isin(SPAM_CATEGORIES)).all())
        self.assertTrue((self.f[self.f.final_label == "legitimate"].scam_group == "none").all())
        self.assertTrue((self.f[self.f.final_label == "review"].scam_group == "unassigned").all())

    def test_no_group_leakage_between_any_two_partitions(self):
        gs = {n: self.grp(d) for n, d in self.parts.items()}; gs["benchmark"] = self.grp(self.bench)
        names = list(gs)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                self.assertFalse(gs[names[i]] & gs[names[j]], f"{names[i]} / {names[j]}")

    def test_no_normalised_text_shared_between_partitions(self):
        t = {n: set(d.message.map(norm)) for n, d in self.parts.items()}; t["benchmark"] = set(self.bench.message.map(norm))
        names = list(t)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                self.assertFalse(t[names[i]] & t[names[j]], f"{names[i]} / {names[j]}")

    def test_language_test_sets_are_outside_training_and_validation(self):
        trv = set(self.parts["train"].message_id) | set(self.parts["validation"].message_id)
        for n in ("test_hindi", "test_hinglish"):
            d = self.parts[n]; self.assertFalse(set(d.message_id) & trv)
            self.assertEqual(set(d.source), {"indian_scam_synthetic"}); self.assertTrue((d.label_status == "awaiting_independent_review").all())
        self.assertEqual(set(self.parts["test_hindi"].language), {"Hindi"}); self.assertEqual(set(self.parts["test_hinglish"].language), {"Hinglish"})

    def test_main_test_has_only_real_high_confidence_messages(self):
        t = self.parts["test"]; self.assertTrue(set(t.origin_type) <= {"real", "hand_written"}); self.assertFalse((t.final_confidence == "low").any())

    def test_benchmark_is_held_out(self):
        ids = set(self.bench.message_id)
        for n, d in self.parts.items(): self.assertFalse(ids & set(d.message_id), n)

    def test_spam_and_fraud_are_both_covered_in_training(self):
        tr = self.parts["train"]; s = tr[tr.final_label == "scam"]
        self.assertGreater((s.scam_group == "spam").sum(), 1000); self.assertGreater((s.scam_group == "fraud").sum(), 1000)
        self.assertGreater(s.scam_category.nunique(), 10)

    def test_languages_and_scripts_are_recorded(self):
        self.assertTrue(set(self.f.script) <= {"Devanagari", "Latin", "Mixed", "Other"})
        hi = self.f[(self.f.language == "Hindi") & (self.f.source != "benchmark_ground_truth")]
        self.assertGreater((hi.script.isin(["Devanagari", "Mixed"])).mean(), 0.99)

    def test_new_sources_are_integrated_with_origin_flags(self):
        for src, origin in [("indian_scam_synthetic", "synthetic_llm"), ("hindi_15k_templated", "templated_synthetic")]:
            d = self.f[self.f.source == src]; self.assertGreater(len(d), 0, src); self.assertEqual(set(d.origin_type), {origin})
        self.assertEqual(len(self.f[self.f.source == "indian_scam_synthetic"]), 1580)
        self.assertEqual(len(self.f[self.f.source == "hindi_15k_templated"]), 60)       # 15,000 rows -> 60 unique messages

    def test_message_ids_unique(self):
        self.assertFalse(self.f.message_id.duplicated().any())


if __name__ == "__main__":
    unittest.main()
