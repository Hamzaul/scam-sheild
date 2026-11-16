"""Regression tests for the final-label adjudicator. Run: python -m unittest discover -s tests -t . -v"""
import unittest
from scripts.Adjudicate import decide, load_manual

M = load_manual()
def lab(text, kind="spam", source="smishing_bundle", quality="preprocessed_lemmatized", sid="x"):
    return decide(source, sid, text, kind, quality, "", M)[0]

class AdjudicateTests(unittest.TestCase):
    def test_pib_confirmed_india_post_message_is_scam_even_if_source_says_legitimate(self):
        t = "India Post: Your parcel has arrived at the warehouse but cannot be delivered due to incomplete address information. Please use the link below to confirm your address within 12 hours. https://bit.ly/3KM4J5k"
        self.assertEqual(lab(t, kind="legit"), "scam")

    def test_rbi_style_kyc_block_with_link_is_scam(self):
        self.assertEqual(lab("Dear SBI user your account will be blocked today. Update your PAN card KYC now: http://bit.ly/xyz"), "scam")

    def test_genuine_otp_is_legitimate(self):
        self.assertEqual(lab("Your OTP is 482910. Valid for 10 minutes. Do not share this code with anyone."), "legitimate")
        self.assertEqual(lab("G-312106 is your Google verification code.", kind="fraud"), "legitimate")

    def test_unsolicited_promotion_is_scam_spam_under_policy_v2(self):
        r = decide("x", "y", "End of season sale! Flat 50% off at Shoppers Stop. Use code SS50. Visit your nearest store. T&C apply", "spam", "raw", "", M)
        self.assertEqual((r[0], r[5]), ("scam", "UNSOLICITED_PROMO"))

    def test_telecom_data_offer_is_scam_spam(self):
        self.assertEqual(lab("Get 2GB data for Rs 99 valid 7 days. Dial *121# to activate this offer. Recharge now"), "scam")

    def test_hinglish_family_emergency_is_scam(self):
        self.assertEqual(lab("Mummy ko hospital me admit karaya hai, emergency me paise chahiye. Please send Rs 20,000 to this account number immediately", source="hinglish_hf", quality="hand_written"), "scam")

    # --- digital-arrest scripts: coercive lines are scams, authority-only / accusation-only fragments are not decided
    def test_coercive_digital_arrest_lines_are_scam(self):
        for t in ["Crime Branch se bol raha hoon. Aapke number se pornographic material WhatsApp groups mein bheja ja raha hai. FIR ho chuki hai.",
                  "CBI se bol raha hoon. Aapka Aadhaar deactivate hone wala hai. Turant update kijiye.",
                  "Cyber Crime Department se bol raha hoon. Congratulations! Aapne \u20b940 lakh ka lottery jeeta hai. Processing fee dena hoga.",
                  "Amazon se bol raha hoon. Aapka parcel hold hai, clearance charge \u20b9499 dena hoga."]:
            with self.subTest(t=t):
                self.assertEqual(lab(t, source="ysangam_hinglish", quality="templated"), "scam")

    def test_authority_only_or_accusation_only_fragments_go_to_review(self):
        for t in ["Delhi Police se bol raha hoon. Aapke naam par registered SIM ka misuse report hua hai.",
                  "ACP Sharma bol raha hoon. Police verification complete karna zaroori hai.",
                  "Ji namaskar Aapke naam par ek criminal complaint register hui hai.",
                  "Madam ek minute Investigation ke liye aapki identity verify karni hogi.",
                  "Hello ji Aapka mobile number cyber fraud investigation mein aaya hai."]:
            with self.subTest(t=t):
                self.assertEqual(lab(t, source="ysangam_hinglish", quality="templated"), "review")

    def test_same_ambiguous_text_is_not_scam_regardless_of_source(self):
        self.assertNotEqual(lab("Delhi Police se bol raha hoon. Aapke naam par registered SIM ka misuse report hua hai."), "scam")

    def test_anti_scam_advisory_mentioning_digital_arrest_is_not_scam(self):
        self.assertNotEqual(lab("Beware of digital arrest scams. Police and CBI never arrest anyone on a video call. Report to 1930."), "scam")

    def test_benign_ysangam_line_stays_legitimate(self):
        self.assertEqual(lab("Doctor appointment kal 9 baje hai, fasting rehna.", kind="legit", source="ysangam_hinglish", quality="templated"), "legitimate")

    def test_garbled_machine_translation_is_left_in_review(self):
        self.assertEqual(lab("आप नवीनतम नीक फोन की गारंटी दे रहे हैं, एक 40GBP3 खिलाड़ी या एक पाउंड के इनाम!", source="kaggle_hindi_bundle", quality="machine_translated"), "review")

    def test_manual_decision_overrides_and_keeps_hard_cases_in_review(self):
        # read individually: could be a real fraud alert or a smishing template -> review
        self.assertEqual(decide("benchmark_ground_truth", "real_077392", "x", "legit", "curated_small", "", M)[0], "review")
        self.assertEqual(decide("benchmark_ground_truth", "real_077393", "x", "legit", "curated_small", "", M)[0], "scam")

    def test_vague_message_without_evidence_is_review(self):
        self.assertEqual(lab("Dear customer your outgoing service put on hold please call"), "review")

    def test_you_wont_is_not_you_won(self):
        self.assertNotEqual(lab("We can close in a week and you won't have any REALTOR fees, call now"), "scam")

if __name__ == "__main__":
    unittest.main()


class CleaningTests(unittest.TestCase):
    def test_placeholders_and_destroyed_text_are_detected(self):
        from scripts.cleaning import is_placeholder
        for t in ["null", "NULL", " None ", "nan", "N/A", "", "   ", None, float("nan"), "??????", "?????????? ", "...", "-"]:
            with self.subTest(t=t):
                self.assertTrue(is_placeholder(t))

    def test_real_messages_are_kept(self):
        from scripts.cleaning import is_placeholder
        for t in [":)", ":-) :-)", "OK", "WIFI", "No", "Na bhai kal aana", "\u0905\u092a\u0928\u093e \u0913\u091f\u0940\u092a\u0940 \u092c\u0924\u093e\u0907\u090f", "123456", "Nil balance in your account. Recharge now"]:
            with self.subTest(t=t):
                self.assertFalse(is_placeholder(t))

    def test_final_dataset_has_no_placeholder_messages(self):
        import os, pandas as pd
        from scripts.cleaning import is_placeholder
        path = "data/processed/final_dataset.csv"
        if not os.path.exists(path): self.skipTest("final_dataset.csv not built yet")
        df = pd.read_csv(path, keep_default_na=False)
        self.assertEqual(int(df.message.map(is_placeholder).sum()), 0)
        for split in ("train", "validation", "test"):
            part = pd.read_csv(f"data/processed/{split}.csv", keep_default_na=False)
            self.assertEqual(int(part.message.map(is_placeholder).sum()), 0, split)


from scripts.Adjudicate import Adjudicate_frame, hindi_category, official_links_only, strip_ids, SPAM_CATEGORIES

def full(text, kind="spam", source="smishing_bundle", quality="preprocessed_lemmatized", sid="x"):
    return decide(source, sid, text, kind, quality, "", M)

class PolicyV2MappingTable(unittest.TestCase):
    """the owner's mapping table: fraud/spam/ads -> scam ; genuine notices, OTPs, delivery alerts, personal -> legitimate ; uncertain -> review"""
    def test_fraud_rows_are_scam_with_fraud_group(self):
        for text, cat in [("Dear SBI user your account will be blocked today. Update your PAN card KYC now: http://bit.ly/xyz", "KYC"),
                          ("Congratulations! You have won Rs 10,00,000. Claim your prize by calling 8899001122.", "LOTTERY_PRIZE"),
                          ("Your parcel is held. Update address today at https://parcel-check.example", "DELIVERY")]:
            with self.subTest(text=text):
                r = full(text); self.assertEqual(r[0], "scam"); self.assertEqual(r[5], cat); self.assertNotIn(r[5], SPAM_CATEGORIES)

    def test_bulk_advertising_and_bulk_job_loan_ads_are_scam_spam(self):
        for text, cat in [("Flash sale! Up to 70% off on all shoes. Visit our store this weekend. T&C apply", "UNSOLICITED_PROMO"),
                          ("Get a personal loan instantly at low interest. Apply now! T&C apply", "BULK_JOB_LOAN_AD"),
                          ("Hiring! Walk-in interview for sales executive, salary 20000. Call now", "BULK_JOB_LOAN_AD")]:
            with self.subTest(text=text):
                r = full(text); self.assertEqual((r[0], r[5]), ("scam", cat)); self.assertIn(r[5], SPAM_CATEGORIES)

    def test_genuine_notifications_stay_legitimate(self):
        for text in ["Your OTP is 482910. Valid for 10 minutes. Do not share this code with anyone.",
                     "Rs 1,200.00 debited from A/c XX4521 on 12-Oct. Avl bal Rs 8,540. If not you call 1800 123 4567",
                     "Your order #4521 has been shipped and will be delivered tomorrow by Delhivery."]:
            with self.subTest(text=text): self.assertEqual(full(text)[0], "legitimate")

    def test_personal_message_stays_legitimate(self):
        self.assertEqual(full("Mummy ne kaha ghar aate waqt doodh le aana", kind="legit")[0], "legitimate")

    def test_promo_content_labelled_legitimate_by_its_source_goes_to_review(self):
        self.assertEqual(full("Flat 50% off at Shoppers Stop. Use code SS50. Visit your nearest store. T&C apply", kind="legit")[0], "review")

    def test_uncertain_message_is_review(self):
        self.assertEqual(full("Dear customer your outgoing service put on hold please call")[0], "review")


class FixesFoundByDatasetD(unittest.TestCase):
    def test_message_that_asks_you_to_tell_the_otp_is_not_a_genuine_otp(self):
        self.assertEqual(full("Namaskar, me Bank manager boltoy. Tumchya ATM card chi expiry date sampali ahe, te renew karnyasathi ha OTP mala sanga: 8352", kind="fraud")[0], "scam")
        self.assertEqual(full("Hey! aapka PhonePe account block hone wala hai, KYC complete karo ASAP. OTP: 849302.", kind="fraud")[0], "scam")

    def test_disconnection_threat_with_app_or_deadline_is_not_a_service_notice(self):
        for text in ["Reminder: aapka pending bill Rs. 1,980. Payment kar do, nahi to connection cut ho jayega. No time waste!",
                     "Hi, pending electricity bill Rs.2,640. Pay through our app or your connection will be shut down at 9 PM."]:
            with self.subTest(text=text): self.assertEqual(full(text, kind="fraud")[0], "scam")

    def test_only_official_domain_link_is_not_phishing(self):
        t = "ALERT: Your SBI login from new device detected. If not you, secure account now at https://www.onlinesbi.com/security"
        self.assertTrue(official_links_only(t.lower()))
        self.assertNotEqual(full(t, kind="legit")[0], "scam")
        self.assertEqual(full("SBI KYC update required, click http://sbi-kyc-update.xyz/verify or account will be blocked")[0], "scam")

    def test_account_and_reference_numbers_are_not_phone_numbers(self):
        self.assertNotEqual(full("Your State Electricity Board account 6392748190 has a pending amount of Rs. 2,980. Please clear by 10-Nov to avoid penalty.", kind="legit")[0], "scam")
        self.assertNotIn("6392748190", strip_ids("account 6392748190 pending"))

    def test_sentence_ending_full_stop_is_not_a_subdomain_trick(self):
        self.assertNotEqual(full("Your UIDAI update request is processed. Details at https://uidai.gov.in.", kind="legit")[0], "scam")

    def test_visit_home_branch_is_an_official_channel(self):
        self.assertNotEqual(full("SBI Notice: Dear account holder, as per RBI guidelines submit updated KYC documents at your home branch within 30 days to avoid restriction.", kind="legit")[0], "scam")


class HindiTemplates(unittest.TestCase):
    """all 60 unique messages of hindi_sms_spam_ham_15000.csv were read by hand; these are representative"""
    def test_categories(self):
        for text, cat in [("केवाईसी अपडेट नहीं करने पर आपकी सेवा बंद हो सकती है। अभी सत्यापन करें।", "KYC"),
                          ("आपका बैंक खाता बंद होने वाला है। सत्यापन पूरा करने के लिए तुरंत दिए गए लिंक पर जाएं।", "BANKING"),
                          ("आपने 5000 रुपये का बोनस जीता है। बोनस लेने के लिए तुरंत अपना विवरण भरें।", "LOTTERY_PRIZE"),
                          ("तुरंत ऋण पाएं, किसी दस्तावेज की जरूरत नहीं। आवेदन करने के लिए अभी संपर्क करें।", "BULK_JOB_LOAN_AD"),
                          ("आज की फ्लैश सेल में 30% तक की छूट उपलब्ध है। अभी खरीदारी करें।", "UNSOLICITED_PROMO"),
                          ("घर बैठे पैसे कमाने का आसान मौका। आज ही जुड़ें और कमाई शुरू करें।", "JOB_FRAUD")]:
            with self.subTest(text=text): self.assertEqual(hindi_category(text), cat)

    def test_personal_hindi_chat_has_no_category(self):
        for text in ["भाई, अपना फोन चार्ज करके रखना, शाम को बात करनी है।", "कल सुबह 9 बजे कॉलेज के लिए निकलना है।", "जन्मदिन की बहुत-बहुत शुभकामनाएं, तुम्हारा दिन अच्छा रहे।"]:
            with self.subTest(text=text): self.assertIsNone(hindi_category(text))

    def test_hindi_spam_and_ham_decisions(self):
        self.assertEqual(full("आपका बैंक खाता बंद होने वाला है। सत्यापन पूरा करने के लिए तुरंत दिए गए लिंक पर जाएं।", source="hindi_15k_templated", quality="templated")[0], "scam")
        self.assertEqual(full("भाई, अपना फोन चार्ज करके रखना, शाम को बात करनी है।", kind="legit", source="hindi_15k_templated", quality="templated")[0], "legitimate")


class FrameAndHumanLabels(unittest.TestCase):
    def test_scam_group_and_category_columns(self):
        import pandas as pd
        df = pd.DataFrame({"source": ["s"] * 3, "source_id": ["1", "2", "3"], "source_kind": ["spam", "spam", "legit"], "source_quality": ["raw"] * 3,
            "original_label": [""] * 3, "scam_category": ["unassigned"] * 3,
            "message": ["Flat 50% off. Use code SS50. Visit our store. T&C apply", "Dear SBI user account will be blocked today update KYC http://bit.ly/x", "see you at 5"]})
        out = Adjudicate_frame(df)
        self.assertEqual(list(out.final_label), ["scam", "scam", "legitimate"])
        self.assertEqual(list(out.scam_group), ["spam", "fraud", "none"])
        self.assertEqual(out.final_category.iloc[2], "none")

    def test_independent_human_label_overrides_and_unsure_goes_to_review(self):
        import pandas as pd, tempfile, os
        from scripts.finalize_dataset import apply_human_labels
        d = pd.DataFrame({"message_id": ["A", "B", "C"], "final_label": ["scam", "legitimate", "scam"], "final_method": ["rule_scam"] * 3,
                          "final_confidence": ["medium"] * 3, "final_reason": [""] * 3, "scam_category": ["UNSOLICITED_PROMO", "none", "KYC"],
                          "scam_group": ["spam", "none", "fraud"]})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "h.csv")
            pd.DataFrame({"message_id": ["A", "B", "C"], "reviewer_label": ["legitimate", "scam", "unsure"], "reviewer_category": ["", "BANKING", ""]}).to_csv(path, index=False)
            out, n = apply_human_labels(d, path)
        self.assertEqual(n, 3)
        self.assertEqual(list(out.final_label), ["legitimate", "scam", "review"])
        self.assertEqual(list(out.scam_group), ["none", "fraud", "unassigned"])
        self.assertEqual(list(out.final_method), ["human_review"] * 3)

    def test_manual_decision_for_benchmark_ad_was_remapped_to_scam_spam(self):
        r = decide("benchmark_ground_truth", "real_077367", "x", "legit", "curated_small", "", M)
        self.assertEqual((r[0], r[5]), ("scam", "UNSOLICITED_PROMO"))
        self.assertEqual(decide("benchmark_ground_truth", "real_077376", "x", "legit", "curated_small", "", M)[0], "legitimate")
