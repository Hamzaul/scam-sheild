import pandas as pd

df = pd.read_csv("data/processed/train.csv")

print("\n===== DATASET SHAPE =====")
print(df.shape)

print("\n===== COLUMN NAMES =====")
print(df.columns.to_list())

print("\n===== FIRST 5 MESSAGES =====")
print(df[["message", "final_label"]].head())
print("\n===== LABEL DISTRIBUTION =====")
print(df["final_label"].value_counts())
print("\n===== MISSING VALUES =====")
print(df[['message', 'final_label']].isnull().sum())

print("\n===== LANGUAGE DISTRIBUTION =====")

if "language" in df.columns:
    print(df["language"].value_counts())
    
print("\n===== INSPECTION COMPLETED =====")