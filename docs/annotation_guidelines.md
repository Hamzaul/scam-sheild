# Annotation guidelines v0.4 - label policy v2

**Target:** `scam` vs `legitimate`, with `review` for anything uncertain. Unwanted bulk advertising now counts as `scam`; the `scam_category`
(and the derived `scam_group` = `spam` | `fraud`) keeps ordinary spam distinguishable from financial fraud for later analysis.

| Original message type | Final label | scam_category (examples) | scam_group |
|---|---|---|---|
| Fake KYC / OTP theft | scam | KYC, OTP_CREDENTIAL, BANKING | fraud |
| UPI / payment fraud | scam | UPI_PAYMENT | fraud |
| Fake courier / lottery | scam | DELIVERY, LOTTERY_PRIZE | fraud |
| Unwanted bulk advertising | scam | UNSOLICITED_PROMO | spam |
| Unsolicited promotional SMS | scam | UNSOLICITED_PROMO | spam |
| Unwanted bulk job / loan advertisements | scam | BULK_JOB_LOAN_AD | spam |
| Genuine bank notifications | legitimate | none | none |
| Genuine OTP messages | legitimate | none | none |
| Genuine delivery alerts | legitimate | none | none |
| Normal personal messages | legitimate | none | none |
| Uncertain messages | review | unassigned | unassigned |

Other fraud categories used: ADVANCE_FEE, DIGITAL_ARREST, FAMILY_EMERGENCY, MALWARE_APK, JOB_FRAUD, INVESTMENT, LOAN_FRAUD, UTILITY, TOLL_FEE,
IMPERSONATION, PHISHING, REMOTE_ACCESS, OTHER_FRAUD. `SPAM_CATEGORIES = {UNSOLICITED_PROMO, BULK_JOB_LOAN_AD}`; everything else is fraud.

**This reverses the earlier policy (v1: "an ordinary advertisement is not a scam").** Rows and manual decisions were re-mapped (24 benchmark advertisements went from legitimate to scam).

## Decision rules (applied in this order by `scripts/Adjudicate.py`)
1. **Fraud evidence wins**: credential/OTP request, advance fee, fake prize, impersonation + threat + a way to act, look-alike or brand-hyphen links, APK, income-task lures, utility disconnection threats, authority + pressure ("digital arrest"), ... A link whose host is the brand's *official* domain is not phishing by itself.
2. **Genuine notification/service/personal messages stay legitimate**: OTP that does not ask you to share it, transaction alert with no link and a toll-free/branch/app channel, order/delivery status, service notice, advisory, personal chat. A bank notice that also threatens disconnection or asks for the code is *not* genuine.
3. **Promotional / bulk-advert / bulk job-loan content -> scam (spam group)** when the source says spam/unwanted. If the *source* called the message legitimate but the content is promotional, it is **review**: "unsolicited?" cannot be told from the text.
4. Source says legitimate and nothing contradicts it -> legitimate. Source says spam but the text is not commercial (quotes, news, event notices) -> review.

## Hard cases
- Genuine-looking bank/KYC notice with only an official domain or branch visit -> legitimate (not phishing), but a mobile-number callback is suspicious.
- Authority or accusation **alone** ("Police se bol raha hoon...", "criminal complaint register hui hai") is not enough; it needs money, credentials, a coercive consequence (FIR, arrest, freeze) or an instruction to act now.
- `review` is a temporary state. It is excluded from every train / validation / test split.

## Language, script, origin
- `language`: English, Hindi (Devanagari), Hinglish (romanised Hindi mixed with English), Other_CodeMixed (Bengali/Marathi/Telugu/Tamil + English, mostly romanised).
- `script`: Devanagari / Latin / Mixed / Other, measured from the text; `language_detected` is a word-list check kept for audit.
- `origin_type`: real, hand_written, curated_benchmark, synthetic_llm, templated_synthetic, machine_translated. Only real / hand-written messages may enter the main test split.

## Status values
`label_policy` = v2 on every row. `final_method`: manual_read, family_read, family_review, rule_scam, rule_legit, source_label, rule_conflict, unresolved, **human_review** (set when an independent human label is applied). `final_confidence`: high / medium / low.

## Independent human review (not done yet)
Sample: `python -m scripts.make_human_review_sample`. Language test sets: `data/interim/test_hindi_blind_review.csv`, `test_hinglish_blind_review.csv`.
Reviewer fills `reviewer_label` (scam / legitimate / unsure) and, for scams, `reviewer_category`. Then `python -m scripts.collect_human_labels` and
`python -m scripts.finalize_dataset` apply the human labels as overrides. Score agreement with `python -m scripts.score_human_review` (population-weighted).
