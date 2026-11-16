"""Quick integrity check of the final dataset (replaces the old check_labels.py that read label_audit.csv)."""
from pathlib import Path
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "data" / "processed" / "final_dataset.csv", keep_default_na=False)
print("Total rows:", len(df))
print("\nFinal label distribution:\n", df.final_label.value_counts(dropna=False))
print("\nSource class -> final label:\n", pd.crosstab(df.source_kind, df.final_label, margins=True))
print("\nBy source:\n", pd.crosstab(df.source, df.final_label, margins=True))
print("\nMissing final labels:", df.final_label.isna().sum())
print("Rows still in review:", (df.final_label == "review").sum())
print("Duplicate message_id:", df.message_id.duplicated().sum())
