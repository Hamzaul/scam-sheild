# Dataset sources and status (v2)

## Files received so far
| File(s) | What it is | Used? |
|---|---|---|
| `SMSSpamCollection`, `SMSSpamCollection_1` | identical (same md5) UCI SMS Spam Collection | yes (once) |
| `data.json`, `data_1.json`, `hinglish_scam.json`, `hinglish_scam_text_data.json` | **four identical copies** of the "Hinglish" file; ~96% of it is verbatim UCI text; 87 unique new rows | yes (once) |
| `indian_scam_synthetic.csv`, `indian_scam_synthetic_1.csv` | **identical 15-byte error file ("Entry not found")** — Dataset D is still missing | no |
| `train.jsonl`, `val.jsonl`, `test.jsonl` | a pre-merged third-party bundle, 85,680 rows, 7 source datasets, with `is_scam`, `head2_scam_intent`, language | yes, **with re-labelling** (below) |
| `phishing_messages.csv`, `phishing_campaigns.csv` | unlabelled European casino/betting/phishing SMS. In `phishing_messages.csv` the message text sits in the `destination number` column (headers shifted). | **no** — no labels, not Indian, nearly no overlap with the bundle |

Dataset D: all copies you uploaded are the same error page. Download the CSV from the Hugging Face page (*Files and versions*) and save it as
`data/raw/public_datasets/indian_scam_sms_synthetic_audited.csv`; the loader is already in the script. Dataset B (IEEE Hindi) is still not obtained.

## What the bundle (`*.jsonl`) contains — and why we did not trust its labels
| bundle source | rows | observed quality | our `source_quality` |
|---|---|---|---|
| Smishing_Dataset | 69,418 | real SMS, but **lemmatised/digit-masked** ("have be block", "XX"), some mojibake; contains 1,564 UCI texts | preprocessed_lemmatized |
| UCI_SMS_Spam | 5,154 | duplicate of file A | raw |
| Kaggle_Hindi_Merged | 4,567 | Devanagari text that looks **machine-translated from UCI** (e.g. "2006 FIFA वर्ल्ड कप", "एक पाउंड के इनाम"); 4,474 legit / 93 scam | machine_translated |
| Synthetic_Tier_C | 3,720 | synthetic Hindi/Hinglish | synthetic |
| Indian_Telecom_SMS | 2,033 | real-looking mixed content incl. personal chat and trading chatter | raw_mixed |
| ysangam/Indian_Cyber_Scam_Hinglish | 743 | highly templated "Police se bol raha hoon…" scripts | templated |
| Benchmark_Ground_Truth | 45 | small curated set (Hindi/Hinglish/English) | curated_small |

Problems found:
1. **`is_scam=1` includes 24,312 "General Spam / Telemarketing" rows.** Same issue as UCI. Not mapped to scam.
2. **`head2_scam_intent` is noisy.** "UPI Fraud" includes plain cashback/retail promos (PVR, Freecharge, Shoppers Stop); digital-arrest scripts are labelled "General Spam"; the "Legitimate" class contains fake USPS / India Post / AnPost parcel links and a crypto-group lure; the benchmark labels the fake India Post parcel link "Legitimate".
3. **The bundle's own splits leak.** Measured on a 2,000-row sample of its Smishing test rows: 21.6% have a near-duplicate (cosine >= 0.8) in train (13.3% at >= 0.9); 641 normalised texts appear in more than one split, 22 with conflicting labels.
4. **Language tags are unreliable** (e.g. English parcel scam and English chain letters tagged Hinglish). Rows where the declared tag and our word-list heuristic disagree are marked `language_status=needs_review`.
5. **Hindi is almost entirely machine-translated and single-class**: after re-labelling, 4,466 Hindi rows are legitimate and 0 are scam; the 137 Hindi scams are synthetic. A model can learn "Hindi => legitimate". Do not train/evaluate Hindi on this alone.
6. **Provenance/licences are not stated** for Smishing_Dataset, Kaggle_Hindi_Merged, Indian_Telecom_SMS, Synthetic_Tier_C or Benchmark_Ground_Truth. Please supply source URLs and licences before publishing anything derived from them.

## Merge and de-duplication
Order of priority (first copy wins): UCI raw, Hinglish JSON, bundle (benchmark, ysangam, telecom, synthetic, Kaggle Hindi, Smishing, UCI-in-bundle), then D.
Exact duplicates are removed after normalisation (case, punctuation, digits): 95,041 -> 79,798 rows. Identical texts with conflicting source classes are kept once as `review`.

## Splitting and leakage
`template_id` = near-duplicate groups (MinHash-LSH over word 3-shingles, Jaccard >= 0.7). Splits are stratified and grouped by `template_id`:
- Any group containing the **benchmark** rows is reserved (`data/processed/heldout_benchmark_candidates.csv`) and appears in no split.
- **Synthetic, machine-translated and templated** rows can only be in train/validation (never test); a group is test-eligible only if all its rows are.
- The script asserts that no group crosses splits. `label == review` rows are excluded from all splits.
- **The dev `test.csv` is 99.8% English** (7,180 rows, 360 scams; mostly preprocessed Smishing + UCI). It is a development test only — **not** the independent Indian/Hindi/Hinglish test set. The 45-row benchmark is the only independent Indian-language material we have, and its own labels need review.
