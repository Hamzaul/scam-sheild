from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "data" / "interim" / "label_audit.csv"

df = pd.read_csv(FILE)

print("\nFinal label distribution:")
print(df["final_label"].value_counts(dropna=False))

print("\nLabel distribution by source:")
print(pd.crosstab(df["source"], df["final_label"]))

print("\nMissing final labels:")
print(df["final_label"].isna().sum())

print("\nRemaining review rows:")
print((df["final_label"] == "review").sum())

print("\nDuplicate messages:")
print(df["message"].duplicated().sum())