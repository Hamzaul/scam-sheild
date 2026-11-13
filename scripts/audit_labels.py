from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

INPUT_FILE = ROOT / "data" / "interim" / "merged_dataset.csv"
OUTPUT_FILE = ROOT / "data" / "interim" / "label_audit.csv"

df = pd.read_csv(INPUT_FILE)

# Preserve the original label for traceability.
df["original_label"] = df["label"]

# Create a new label column using our final classification scheme.
df["final_label"] = ""

# UCI ham messages become legitimate.
df.loc[
    (df["source"] == "uci_sms_spam") &
    (df["original_label"] == "ham"),
    "final_label"
] = "legitimate"

# UCI spam messages need manual review:
# some may be ordinary promotions rather than scams.
df.loc[
    (df["source"] == "uci_sms_spam") &
    (df["original_label"] == "scam"),
    "final_label"
] = "review"

# Keep non-UCI labels for manual verification too.
# Do not automatically trust an imported dataset's label.
df.loc[
    df["source"] != "uci_sms_spam",
    "final_label"
] = "review"

df.to_csv(OUTPUT_FILE, index=False)

print("Label audit file created successfully!")
print(f"Saved to: {OUTPUT_FILE}")
print("\nFinal-label counts:")
print(df["final_label"].value_counts(dropna=False))

print("\nRows requiring manual review:")
print((df["final_label"] == "review").sum())