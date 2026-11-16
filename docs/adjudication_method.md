# How the final labels were decided (policy v2)

Policy (project owner): fraud, fake KYC/OTP, UPI/payment fraud, fake courier/lottery **and** unwanted bulk advertising, unsolicited promotional SMS and unwanted bulk
job/loan adverts are **scam**; genuine bank notifications, genuine OTPs, genuine delivery alerts and normal personal messages are **legitimate**; uncertain = **review**.
`scam_category` / `scam_group` (spam vs fraud) are kept. See `docs/annotation_guidelines.md` for the table and decision order.

## Evidence
- External: RBI KYC/OTP advisories; I4C/MHA "digital arrest" advisories; PIB Fact Check (India Post "incomplete address" SMS is fake); TRAI header rules (regulated promotional vs transactional SMS).
- Read directly: all 45 benchmark rows and 87 hand-written Hinglish rows (`data/interim/manual_decisions.csv`, 132 decisions, 24 advertisements re-mapped to scam under v2), all 60 unique messages of the Hindi 15k file, ~60 synthetic Hindi/Hinglish rows, the YSangam script lines, and several hundred messages across the other pools while writing the rules.
- **Dataset D's own labels** were used as an independent check on the rules (they were generated separately and never used to write rules): the first run disagreed on 25 messages; each was read, which exposed seven real rule defects (OTP rule accepted "tell me the OTP"; disconnection threats read as notices; official-domain links flagged; 10-digit account numbers counted as phones; sentence-final ".gov.in." read as a subdomain trick; "home branch" not an official channel; Devanagari "cut हो जाएगी" missed). After fixing them D disagreements fell to 3 of 1,580 (all arguable).

## Order of decision (`scripts/Adjudicate.py`)
manual_read -> family decisions (garbled translations -> review; synthetic fraud templates with a concrete lure -> scam; call-script lines -> scam only with authority + pressure) -> fraud evidence (9 base rules in `triage_rules.py` + ~60 extended families) -> genuine notification/service/advisory rules -> promotional / bulk-ad / job-loan content (scam-spam if the source says spam; **review** if the source says legitimate) -> source label -> review.
Every row records `final_method`, `final_reason`, `final_confidence`, `final_signals`, `scam_category`, `scam_group`, `label_policy`.

## Result (81,437 messages)
| label | rows | | scam_group | rows |
|---|---|---|---|---|
| legitimate | 52,311 | | fraud | 5,596 |
| scam | 22,408 | | spam | 16,812 |
| review | 6,718 | | | |

Spam vs fraud by language (scam rows): English 16,525 / 4,304; Hindi 13 / 326; Hinglish 259 / 761; Other_CodeMixed 15 / 205.

## Accuracy - what is and is not known
- The 96% / 93% precision figures in the previous version were measured under policy v1 and **do not carry over**. Under v2 only partial checks exist: D disagreements (above), a 28-message read of spam-scam rows (policy-correct; 3 had the wrong category, which led to the delivery / prize / brand-host rules), and a 20-message read of legit-source promos sent to review (about half were personal chat wrongly seen as promo -> promo rule tightened).
- **No independent human has verified any label.** Use `scripts/make_human_review_sample.py` and `scripts/score_human_review.py` (population-weighted) before quoting an accuracy.
- Messages the source called legitimate and that matched no rule (about 49k) are not individually verified.
- Messages left in review (6,718; 5,601 unresolved, 614 rule conflicts, 498 garbled translations): about a quarter of an earlier sample were still scams the rules miss - do **not** treat review as "probably legitimate".
- `benchmark`: 38 scam / 4 legitimate / 3 review under v2 - it can no longer measure false positives.

## Re-running
```
python scripts/build_dataset.py
python -m scripts.finalize_dataset
python -m scripts.evaluate_baseline
python -m unittest discover -s tests -t . -v
```
