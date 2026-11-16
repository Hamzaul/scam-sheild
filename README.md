# Hinglish scam / spam SMS dataset

Label policy v2: scam (fraud **and** unwanted promotion / bulk ads) vs legitimate, `review` when uncertain; `scam_category` / `scam_group` separate spam from fraud.

## Run order
```
pip install -r requirements.txt
python scripts/build_dataset.py            # merge, clean, de-duplicate, group  -> data/interim/merged_dataset.csv
python -m scripts.finalize_dataset         # Adjudicate + partitions + review files + docs/final_audit_report.md
python -m scripts.evaluate_baseline        # docs/model_evaluation_report.md (baseline; class weights from train only)
python -m scripts.make_human_review_sample # blind sample for human verification
python -m unittest discover -s tests -t . -v
```
## Key outputs (`data/processed/`)
`final_dataset.csv` (all messages, final label/category/group/confidence/method/reason), `train|validation|test.csv`, `test_hindi.csv`, `test_hinglish.csv`, `heldout_benchmark_candidates.csv`, `review_remaining.csv`.
Read every CSV with `pd.read_csv(path, keep_default_na=False)`.
## Docs
`docs/annotation_guidelines.md` (policy table), `docs/adjudication_method.md`, `docs/dataset_sources.md`, `docs/evaluation_protocol.md`, `docs/model_evaluation_report.md`, `docs/final_audit_report.md`.
## Status
Labels are NOT independently human-verified. There is no real-world Hindi/Hinglish SMS in the data. Source licences are unconfirmed.
