# Dataset sources and status

## Files received and what they contained
| File | Rows | Genuinely new | Notes |
|---|---|---|---|
| `SMSSpamCollection`, `SMSSpamCollection_1` | 5,574 | - | identical copies (UCI) |
| `data.json`, `data_1.json`, `hinglish_scam.json`, `hinglish_scam_text_data.json`, **`data_e363b4.json`** | 3,787 | 87 | all identical; ~96% is verbatim UCI text |
| `train/val/test.jsonl` | 85,680 | most | third-party bundle of 7 sources (see below) |
| **`synthetic_audited.csv`** (= Dataset D, HF `bhavya2910/...`) | 1,580 | **1,580** | LLM-generated (Gemini, gpt-oss); 0 exact or near-duplicate overlap with existing data; 1,350 rows never reviewed even by the audit |
| **`hindi_sms_spam_ham_15000.csv`** | 15,000 | **60** | only 60 unique messages after digit masking (31 spam / 29 ham): ~130 repeats of each LLM-style template; ham is short chat (avg 40 chars), spam long (73) - a length shortcut |
| `phishing_messages.csv`, `phishing_campaigns.csv` | - | 0 | unlabelled European casino/betting SMS; not merged |
| `indian_scam_synthetic*.csv` (earlier) | 15 bytes | - | an "Entry not found" error page; superseded by `synthetic_audited.csv` |

Merged dataset: **81,437** unique messages (79,797 before the last upload + 1,640 new).

## origin_type (what each source is, observed in the text; provenance documents are still missing)
| source | rows | origin_type | notes |
|---|---|---|---|
| smishing_bundle | 66.7k | real | real SMS but lemmatised / digit-masked, some mojibake |
| uci_sms_spam (+ uci_in_bundle) | 5.1k | real | English, UK/Singapore, older |
| indian_telecom_sms | 1.9k | real | mixed real-looking content incl. personal chat |
| kaggle_hindi_bundle | 4.6k | machine_translated | garbled translations of UCI; 4,425 legitimate, 0 scam |
| indian_scam_synthetic (D) | 1.6k | synthetic_llm | hi 167, hinglish 639, en 262, bn/mr/te/ta-en 512 (mostly romanised) |
| synthetic_tier_c | 0.6k | synthetic_llm | synthetic Hindi/Hinglish notices |
| ysangam_hinglish | 0.7k | templated_synthetic | call-script lines |
| hindi_15k_templated | 60 | templated_synthetic | the 60 unique templates |
| hinglish_hf | 87 | hand_written | hand-written Hinglish |
| benchmark_ground_truth | 45 | curated_benchmark | small curated set; reserved |

**The Hindi/Hinglish shortage is not solved by these files.** Hindi: 4,916 resolved messages, of which 4,425 are machine-translated chat (legitimate) and only 339 are scam (326 fraud, 13 spam), all synthetic or templated.
Hinglish: 1,541 resolved (1,020 scam / 521 legitimate), all synthetic, templated or hand-written. There is **no real-world Hindi or Hinglish SMS** in the data. Ordinary Hindi advertising (spam) is almost absent (13 messages).

## Problems in the third-party bundle (unchanged)
`is_scam` counted promotional spam; fraud categories mixed in cashback ads; the "Legitimate" class contained fake parcel/USPS/India Post/IRS/bank phishing; its own splits leaked (21.6% of its test rows had a near-duplicate in train); language tags were unreliable. Licences/provenance of the bundle sources, D and the Hindi file are **not stated** - verify before publishing.

## De-duplication, cleaning, grouping
Exact duplicates after normalisation (case, punctuation, digits) are removed (first source wins; identical texts with conflicting source classes -> review). Placeholder / destroyed-text rows are removed (`scripts/cleaning.py`: `null`, empty, all-`?`; emoticons are kept).
`template_id` = near-duplicate group (MinHash-LSH, Jaccard >= 0.7; **>= 0.5 inside synthetic / templated / translated sources**, because generated variants are looser paraphrases). Always read CSVs with `keep_default_na=False`.

## Partitions (leakage-safe, whole groups only)
`train`, `validation`, `test` (real/hand-written messages only), `test_hindi` and `test_hinglish` (from Dataset D only - never used to design a rule), `heldout_benchmark_candidates` (45). `finalize_dataset.py` asserts no group is shared between any two partitions.
