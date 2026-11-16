
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
INPUT_FILE = ROOT / "data" / "interim" / "merged_dataset.csv"

df = pd.read_csv(INPUT_FILE)

# Clean source and label values for inspection.
df["source"] = df["source"].fillna("UNKNOWN").astype(str).str.strip()
df["label"] = df["label"].fillna("MISSING").astype(str).str.strip()

print("\n========== DATASET SUMMARY ==========")
print("Total messages:", len(df))
print("Total sources:", df["source"].nunique())

print("\n========== ORIGINAL LABELS BY SOURCE ==========")

label_counts = pd.crosstab(
    df["source"],
    df["label"],
    margins=True
)

print(label_counts.to_string())

print("\n========== SAMPLE MESSAGES BY SOURCE ==========")

for source in sorted(df["source"].unique()):
    print(f"\n--- SOURCE: {source} ---")

    samples = df[df["source"] == source][["label", "message"]].head(3)

    for _, row in samples.iterrows():
        print("Original label:", row["label"])
        print("Message:", str(row["message"])[:250])
        print("-" * 50)
