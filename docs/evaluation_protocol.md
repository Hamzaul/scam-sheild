# Evaluation protocol

## 1. Class imbalance
Resolved data is about 70% legitimate / 30% scam (train: 15,683 scam of 52,966), but the test mix differs by source. A model that predicts "legitimate" for everything scores
about 69% accuracy and catches no scam. Report for the scam class: **precision, recall, F1, PR-AUC** and the confusion matrix; never accuracy alone.
Handle imbalance **with training data only**: class weights computed from `train.csv`, no resampling before splitting, vectorizer fitted on train, threshold chosen on validation, then frozen (`scripts/evaluate_baseline.py` does exactly this).

## 2. Partitions
| file | use | notes |
|---|---|---|
| train / validation | fit / tune | contain synthetic, templated and translated data |
| test | one-time report | real / hand-written messages only; ~99.5% English; 92% from one source (smishing_bundle) |
| test_hindi (146) / test_hinglish (299) | one-time report | from LLM-generated Dataset D; **labels awaiting independent review**; never in train / validation |
| heldout_benchmark_candidates (45) | sanity check | 38 scam / 4 legitimate / 3 review: cannot measure false positives |

No group of near-duplicates is shared between any two partitions (asserted).

## 3. The language test sets are not yet a valid independent test
They are held out and leakage-safe, but (a) synthetic, (b) labelled by rules, (c) small (a 146-message Hindi set has an F1 95% interval about 0.15 wide), and (d) almost all fraud (Hindi: 70 fraud / 4 spam).
To make them valid: have a Hindi/Hinglish reader label `data/interim/test_hindi_blind_review.csv` and `test_hinglish_blind_review.csv` (labels hidden), double-annotate ~20%, then
`python -m scripts.score_human_review --blind <file> --key <key>` and `python -m scripts.collect_human_labels` + `python -m scripts.finalize_dataset`. Best: add real Hindi/Hinglish SMS (>= 300 scam and >= 300 legitimate per language) written or collected independently of any generator, de-duplicated against train.

## 4. Human verification of the general labels
`python -m scripts.make_human_review_sample` -> 1,199 messages in 29 strata (language x label-group x origin; spam and fraud separate; benchmark separate; Hindi scam strata guaranteed).
`python -m scripts.score_human_review` reports, separately: **sample** agreement and ordinary kappa (describe the sample only), and **population-weighted** agreement (with bootstrap CI), weighted kappa, a weighted confusion matrix and per-stratum estimated wrong labels. Do not read sample agreement as dataset accuracy.

## 5. Baseline results (`docs/model_evaluation_report.md`) - how to read them
TF-IDF + logistic regression, F1-optimal threshold chosen on validation: main test F1 0.97 (precision 0.96, recall 0.98); Hindi test F1 0.80; Hinglish test F1 0.87; benchmark F1 0.92 (n = 42).
**Do not quote these as real-world performance**: the labels are automatic, the main test is in-distribution and dominated by one source, and a model can separate "advertisement" from "chat" without understanding fraud.
**The decisive finding is the hard-negative false-positive rate on the main test:** genuine service notices 25.5% (n=149), public information 22%, order status 50% (n=16), advisories 37.5% (n=8), genuine OTPs 40% (n=5), against 0.8% on ordinary legitimate messages. The data has too few genuine notifications; add many more before relying on any precision figure.

## 6. Training hygiene
Keep `review` rows out of training; consider dropping `final_confidence == "low"`; report per language, per source and per scam_group; check the model is not predicting the source (Hindi is almost all translated chat; Tier-C and YSangam are templated); compare several classifiers on identical splits.
