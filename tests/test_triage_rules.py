"""Regression tests for conservative SMS scam triage rules.

Run from the project root:
    python -m unittest discover -s tests -v
"""
import unittest

from scripts.triage_rules import signals, RULES, STRONG


class TriageRulesTests(unittest.TestCase):
    def test_public_interface_and_rule_names_are_preserved(self):
        expected = {
            "cred", "fee", "prize", "imperson", "authority_call",
            "family", "apk", "job", "parcel",
        }
        self.assertEqual(set(RULES), expected)
        self.assertEqual(set(STRONG), expected)
        self.assertIsInstance(signals("ordinary message"), list)

    def test_clear_scam_examples_trigger(self):
        examples = [
            "Your SBI account will be blocked today. Click https://fake-sbi.example/verify",
            "Hello ji Aapka KYC pending hai. Account 2 ghante mein block ho jayega. OTP share kijiye.",
            "Congratulations! You have won ₹10,00,000. Claim your prize now by calling 8899001122.",
            "ACP Sharma bol raha hoon. Police case mein arrest se bachne ke liye apna OTP bataiye.",
            "Aapke father ko accident ho gaya hai. Turant 50,000 bhej dijiye hospital ke liye.",
            "Install this update.apk from https://fake-app.example immediately.",
            "Work from home job: earn ₹5000 per day. Join our Telegram group and register.",
            "Your parcel is held. Update address today at https://parcel-check.example or it will be returned.",
            "Pay the refundable security deposit of ₹999 today to unlock your job task.",
        ]
        for message in examples:
            with self.subTest(message=message):
                self.assertTrue(signals(message), f"Expected a signal for: {message}")

    def test_legitimate_and_warning_examples_do_not_trigger(self):
        examples = [
            "Your Jio recharge was successful. Enjoy 1.5GB daily data.",
            "Never share your OTP with anyone. Your bank will never ask for it.",
            "Do not share your password or PIN with anyone.",
            "Your parcel is out for delivery. The delivery partner will contact you.",
            "Your order has shipped. Track it in the official shopping app.",
            "Your electricity bill payment was successful. Thank you.",
            "Police verification appointment is scheduled for Monday. Carry your ID.",
            "Your account statement is ready to view in the official banking app.",
        ]
        for message in examples:
            with self.subTest(message=message):
                self.assertEqual(signals(message), [])

    def test_delivery_fee_alone_is_not_enough(self):
        self.assertEqual(
            signals("Your parcel is pending. Pay delivery fee at www.example.com"),
            [],
        )

    def test_plain_authority_reference_is_not_enough(self):
        self.assertEqual(
            signals("ACP Sharma bol raha hoon. Police verification complete karna zaroori hai."),
            [],
        )

    def test_plain_fee_or_job_words_are_not_enough(self):
        self.assertEqual(signals("A delivery fee may apply to remote areas."), [])
        self.assertEqual(signals("We have a part-time opening. Apply on our careers page."), [])

    def test_hindi_credential_request(self):
        self.assertIn("cred", signals("अपना ओटीपी और पिन बताइए।"))

    def test_credential_warning_is_not_a_request(self):
        self.assertNotIn("cred", signals("अपना ओटीपी किसी को भी साझा न करें।"))

    def test_empty_and_none_inputs(self):
        self.assertEqual(signals(""), [])
        self.assertEqual(signals("   "), [])
        self.assertEqual(signals(None), [])


if __name__ == "__main__":
    unittest.main()
