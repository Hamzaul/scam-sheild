# Annotation guidelines v0.3

**Target:** `scam` vs `legitimate`. Unwanted or annoying is **not** the same as fraudulent.

## Final-label mapping (applied by `scripts/build_dataset.py`)
| Source label | Final label | Rule |
|---|---|---|
| ham / "Legitimate" | `legitimate` | Only if the text shows **no** scam signal; otherwise `review` (the source's "legitimate" class contains fake parcel/USPS/crypto-group scams). |
| scam / any fraud category | `scam` | Only if the text **meets the scam definition** (>=1 strong signal, see `scripts/triage_rules.py`); otherwise `review` (e.g. "UPI Fraud" rows that are really cashback ads). Status `provisional_scam`. |
| spam / telemarketing / unclear | `review` | Unwanted promo is **not** automatically a scam. Becomes provisional `scam` (status `provisional_auto`) only if it clearly meets the definition. |
| identical text, conflicting source labels | `review` | `conflicting_source_labels` |

`review` is a temporary state: those rows are excluded from train/validation/test until a human resolves them.
All `provisional_*` labels are heuristic and must be confirmed. Strong signals: credential/OTP request, advance fee, fake-prize claim,
organisation impersonation + threat + a way to act, authority "digital arrest" call, emergency-family money request, APK install,
income-task job lure, parcel-address/fee lure. Genuine OTP messages ("do not share") are deliberately not flagged.

## Labels
**scam** — a message intended to deceive the reader into a harmful action, including any of:
- stealing money (fake fees, "processing/security charge", fake refund, advance-fee, investment/job fraud);
- obtaining OTPs, PINs, passwords, card/bank/Aadhaar/PAN details;
- impersonating an organisation or person (bank, KYC, courier, government, electricity board, "your son/relative");
- tricking the reader into a fraudulent action (click a look-alike link, call a fake "officer", install an app, pay to claim a prize that doesn't exist).

**legitimate** — genuine personal, transactional, service, or promotional messages that do not attempt fraud. This includes:
- genuine bank/UPI alerts and OTP messages (even though they contain OTPs and money amounts);
- delivery, bill, recharge, appointment updates;
- ordinary advertisements and unsolicited promotions (discounts, offers, subscription marketing) **unless** they lie about something to extract money/data.

> Do **not** label a message `scam` just because it looks like spam.

## Decision test (apply in order)
1. Does it ask for an OTP/PIN/password/card or bank details, or tell the reader to hand over a code? -> likely `scam` (unless it is a genuine OTP *delivery* message that says not to share it).
2. Does it claim a prize/refund/reward that requires a fee, personal details, or a premium-rate call to "claim"? -> `scam`.
3. Does it impersonate an authority and threaten (block, disconnect, arrest, expire) unless the reader acts through a link/number in the message? -> `scam`.
4. Is it an advertisement, offer, newsletter, or service notice with no deception? -> `legitimate`.
5. Cannot tell from the text alone? -> mark `unsure` in `reviewer_notes` (do not force a label).

## UCI-specific guidance (older UK premium-rate SMS)
- "You have won £1000 — call 09061…/text to claim" lures -> `scam` (deceptive prize).
- Ringtone/tone/dating/chat subscription ads that state price and STOP/opt-out terms -> `legitimate` (unwanted promo) **unless** the price/terms are hidden or the offer is fake. Record the borderline ones in notes; they are the main label-noise risk.
- Adult-chat ads: `legitimate` for this fraud-detection task (we are not building an adult-content filter), noted as `promo`.

## Other columns
- **language:** English; Hindi (Devanagari); Hinglish (romanised Hindi mixed with English); Other_CodeMixed (e.g. Tamil/Telugu/Bengali/Marathi + English).
- **scam_category:** KYC, BANKING, LOTTERY_PRIZE, DELIVERY, JOB, UTILITY, LOAN, IMPERSONATION, INVESTMENT, OTHER; `none` for legitimate.
- **difficulty:** easy (obvious cues) / medium / hard (no link or urgency; or a *legitimate* message that looks like a scam, e.g. a real bank alert with an OTP and a link).
- **label_status** values: `source_label` (label from original dataset), `provisional_auto` (keyword rule; **must be confirmed**), `needs_review` (unresolved; excluded from splits), `synthetic_llm_audited`, `synthetic_unreviewed`, `human_confirmed` (set after review).
- **language_status** values: `heuristic_unreviewed` (word-list guess; **must be confirmed**), `declared_by_generator_prompt`, `fixed_source_english`, `human_confirmed`.

## review_queue.csv
`queue_type` = `full_*` (every row of that type is listed) or `sample_*` (a random sample; `stratum_size` = rows in the whole stratum, so
the fraction of promo vs scam among the sampled rows can be extrapolated). Priority 1 = benchmark rows.
Fill `reviewer_label` (scam/legitimate/unsure), `reviewer_language`, `reviewer_category`, `reviewer_notes`.

## Review workflow
1. Open `data/interim/review_queue.csv`; fill `reviewer_label`, `reviewer_language`, `reviewer_category`, `reviewer_notes` (use a native Hindi/Hinglish speaker for language checks).
2. Double-annotate at least 10-20% of rows with a second annotator; report Cohen's kappa here.
3. Merge decisions back (set `label_status` / `language_status` to `human_confirmed`) and re-run `scripts/build_dataset.py`.
