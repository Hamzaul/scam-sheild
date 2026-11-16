"""Merge public datasets -> data/interim/merged_dataset.csv, review queue, audit report, leakage-safe splits.

Final label target: scam | legitimate  (+ 'review' = temporarily unresolved).  Mapping (docs/annotation_guidelines.md):
  source ham/legitimate        -> legitimate   (unless scam signals are present -> review)
  source scam / fraud category -> scam         ONLY if the text meets the scam definition (triage_rules signals) else review
  source spam / unclear        -> review       (provisional scam only if the text clearly meets the definition)
Run from project root:  python scripts/build_dataset.py
"""
import json, re, sys
from pathlib import Path
import numpy as np, pandas as pd
from datasketch import MinHash, MinHashLSH
from sklearn.model_selection import StratifiedGroupKFold
sys.path.insert(0, str(Path(__file__).parent))
from triage_rules import signals
from cleaning import is_placeholder

RAW = Path("data/raw/public_datasets"); BUNDLE = RAW/"bundle_jsonl"
D_FILE = RAW/"indian_scam_sms_synthetic_audited.csv"
COLS = ["message_id","message","language","label","scam_category","source","difficulty","template_id","original_label",
        "label_status","language_status","source_quality","auto_signals","review_hint","source_id","source_kind",
        "script","language_detected","origin_type"]
SEED = 42
TEST_OK_QUALITY = {"raw","raw_mixed","hand_written","preprocessed_lemmatized"}  # real messages only; synthetic, machine-translated, templated -> train/val
RESERVED_SOURCES = {"benchmark_ground_truth"}            # held out entirely for the independent test set
NO_SIGNAL_LANG_CHECK = {"synthetic"}                     # language declared by generator prompt

DEV = re.compile(r"[\u0900-\u097F]")
HINGLISH_WORDS = set("aapka aapki aapke aapko hai hain nahi nahin karein karo karna hua hui tumhari tumhara mera meri mujhe "
    "paise paisa abhi jaldi turant bhejo bhejein ghar kal aaj baje mummy bahut hum kya kyun liye jayein chahiye zaroor "
    "karaya raha rahi rahe mein hamara apna apne kholo dijiye kripya kijiye karen hoga hogi".split())
def detect_language(t):
    if DEV.search(t): return "Hindi"
    return "Hinglish" if sum(w in HINGLISH_WORDS for w in re.findall(r"[a-z]+", t.lower())) >= 2 else "English"

def detect_script(t):
    """Devanagari / Latin / Mixed (both) / Other (other Indic or no letters)"""
    dev = len(re.findall(r"[\u0900-\u097F]", t)); lat = len(re.findall(r"[A-Za-z]", t))
    if dev and lat: return "Mixed"
    return "Devanagari" if dev else ("Latin" if lat else "Other")

# what each source IS (observed in the text; provenance documents are missing for several): real / hand_written / curated_benchmark /
# synthetic_llm / machine_translated / templated_synthetic
ORIGIN = {"uci_sms_spam":"real","uci_in_bundle":"real","smishing_bundle":"real","indian_telecom_sms":"real","hinglish_hf":"hand_written",
          "benchmark_ground_truth":"curated_benchmark","kaggle_hindi_bundle":"machine_translated","ysangam_hinglish":"templated_synthetic",
          "synthetic_tier_c":"synthetic_llm","indian_scam_synthetic":"synthetic_llm","hindi_15k_templated":"templated_synthetic"}
SYNTHETIC_ORIGINS = {"synthetic_llm","templated_synthetic","machine_translated"}

def fix_text(t):  # light mojibake repair only
    return str(t).replace("ÃÂ£","£").replace("Â£","£").strip()

CAT_MAP = {"Bank Account Freeze":"BANKING","Courier Scam":"DELIVERY","Electricity Disconnection":"UTILITY","Fake KYC":"KYC",
           "Loan Scam":"LOAN","Lottery / Prize":"LOTTERY_PRIZE","OTP / Credential Theft":"BANKING","Telegram Job":"JOB",
           "Traffic e-Challan":"TRAFFIC_CHALLAN","UPI Fraud":"UPI_PAYMENT"}
def cat_kind(head2):  # source-level class: legit / spam / fraud
    return "legit" if head2.startswith("Legit") else ("spam" if head2.startswith("General") else "fraud")

# ---------------- loaders: each returns message, source_kind in {legit,spam,fraud}, original_label, language(declared), ...
def base(df, source, quality, lang_status):
    df["source"], df["source_quality"], df["language_status"] = source, quality, lang_status
    return df

def load_uci():
    d = pd.read_csv(RAW/"SMSSpamCollection", sep="\t", header=None, names=["original_label","message"], quoting=3)
    d["source_kind"] = d.original_label.map({"ham":"legit","spam":"spam"}); d["language"] = "English"
    d["scam_category_src"] = "unassigned"; d["source_id"] = [f"uci_{i}" for i in range(len(d))]
    return base(d, "uci_sms_spam", "raw", "fixed_source_english")

def load_hinglish_json():
    d = pd.DataFrame(json.load(open(RAW/"hinglish_scam_text_data.json"))["rows"]).rename(columns={"text":"message"})
    d["original_label"] = d.label.map({0:"ham",1:"spam"}); d["source_kind"] = d.label.map({0:"legit",1:"fraud"})
    d["language"] = d.message.astype(str).map(detect_language); d["scam_category_src"] = "unassigned"
    d["source_id"] = [f"hf_{i}" for i in range(len(d))]
    return base(d.drop(columns="label"), "hinglish_hf", "hand_written", "heuristic_unreviewed")

BUNDLE_SRC = {  # bundle source_dataset -> (source, source_quality)   (quality = what we OBSERVED in the text)
 "Benchmark_Ground_Truth": ("benchmark_ground_truth","curated_small"),
 "ysangam/Indian_Cyber_Scam_Hinglish": ("ysangam_hinglish","templated"),
 "Indian_Telecom_SMS": ("indian_telecom_sms","raw_mixed"),
 "Synthetic_Tier_C": ("synthetic_tier_c","synthetic"),
 "Kaggle_Hindi_Merged": ("kaggle_hindi_bundle","machine_translated"),
 "Smishing_Dataset": ("smishing_bundle","preprocessed_lemmatized"),
 "UCI_SMS_Spam": ("uci_in_bundle","raw"),
}
def load_bundle():
    a = pd.concat([pd.DataFrame([json.loads(l) for l in open(BUNDLE/f"{n}.jsonl")]) for n in ["train","val","test"]], ignore_index=True)
    out = []
    for sd, (src, q) in BUNDLE_SRC.items():                        # order = dedupe priority (curated first)
        s = a[a.source_dataset==sd]
        d = pd.DataFrame({"message": s.text.values, "original_label": s.head2_scam_intent.values,
                          "source_kind": s.head2_scam_intent.map(cat_kind).values, "language": s.language.values,
                          "scam_category_src": s.head2_scam_intent.map(CAT_MAP).fillna("unassigned").values,
                          "source_id": s.id.values})
        out.append(base(d, src, q, "bundle_declared"))
    return pd.concat(out, ignore_index=True)

D_LANG = {"hinglish":"Hinglish","en":"English","hi":"Hindi"}
D_CAT = {"fake_kyc":"KYC","lottery":"LOTTERY_PRIZE","courier_customs":"DELIVERY","job_offer":"JOB","electricity_bill":"UTILITY",
         "loan_offer":"LOAN","fake_bank_otp":"BANKING","unknown":"OTHER","none":"unassigned"}
def load_d():
    d = pd.read_csv(D_FILE, encoding="utf-8")
    assert {"text","label","original_label","scam_type","language","audit_action","row_id"} <= set(d.columns), "unexpected Dataset D schema"
    o = pd.DataFrame({"message": d.text, "original_label": d.label + "|audit=" + d.audit_action,
        "source_kind": d.label.map({"safe":"legit","scam":"fraud"}), "language": d.language.map(D_LANG).fillna("Other_CodeMixed"),
        "scam_category_src": d.scam_type.map(D_CAT).fillna("OTHER"), "source_id": d.row_id})
    assert o.source_kind.notna().all()
    return base(o, "indian_scam_synthetic", "synthetic", "declared_by_generator_prompt")

def load_hindi15k():
    """hindi_sms_spam_ham_15000.csv: 15,000 rows but only ~60 unique messages (LLM-style templates repeated ~130x, amounts vary).
    Duplicates are removed by the generic exact-dedupe below; what survives is ~60 templated Devanagari messages."""
    d = pd.read_csv(RAW/"hindi_sms_spam_ham_15000.csv", keep_default_na=False).rename(columns={"sms":"message"})
    d["original_label"] = d.label; d["source_kind"] = d.label.map({"ham":"legit","spam":"spam"}); d["language"] = "Hindi"
    d["scam_category_src"] = "unassigned"; d["source_id"] = [f"hi15k_{i}" for i in range(len(d))]
    return base(d.drop(columns="label"), "hindi_15k_templated", "templated", "declared_by_file")

# ---------------- label assignment (the mapping table)
def assign(kind, sig):
    """returns (label, status, hint)"""
    has = bool(sig)
    if kind == "legit":
        return ("legitimate","source_label","") if not has else ("review","needs_review","source_legit_but_scam_signals")
    if kind == "fraud":
        return ("scam","provisional_scam","") if has else ("review","needs_review","source_fraud_label_without_definition_signals")
    return ("scam","provisional_auto","spam_with_scam_signals") if has else ("review","needs_review","spam_or_unclear_likely_promo")

def norm_key(t): return re.sub(r"\s+"," ",re.sub(r"\d","0",re.sub(r"[^a-z0-9\u0900-\u097f ]"," ",t.lower()))).strip()

def template_ids(keys, threshold=0.7, perm=64):
    """near-duplicate groups via MinHash-LSH over word 3-shingles + union-find"""
    mh = []
    for k in keys:
        w = k.split(); sh = {" ".join(w[i:i+3]) for i in range(max(1,len(w)-2))} or {k}
        m = MinHash(num_perm=perm); [m.update(s.encode()) for s in sh]; mh.append(m)
    lsh = MinHashLSH(threshold=threshold, num_perm=perm)
    for i,m in enumerate(mh): lsh.insert(str(i), m)
    parent = list(range(len(keys)))
    def find(x):
        while parent[x]!=x: parent[x]=parent[parent[x]]; x=parent[x]
        return x
    for i,m in enumerate(mh):
        for j in lsh.query(m):
            a,b = find(i), find(int(j))
            if a!=b: parent[max(a,b)] = min(a,b)
    return np.array([find(i) for i in range(len(keys))])

def main():
    parts = [load_uci(), load_hinglish_json(), load_bundle()]
    if (RAW/"hindi_sms_spam_ham_15000.csv").exists(): parts.append(load_hindi15k())
    if D_FILE.exists(): parts.append(load_d())
    else: print(f"NOTE: {D_FILE.name} not found - Dataset D NOT included.")
    df = pd.concat(parts, ignore_index=True)
    ph = df.message.map(is_placeholder)                      # before fix_text: NaN/'null'/'??????' are not messages
    print(f"placeholder / destroyed-text rows removed: {int(ph.sum())}  {df[ph].source.value_counts().to_dict()}")
    df = df[~ph].copy()
    df["message"] = df.message.map(fix_text); n0 = len(df)
    df = df[df.message.str.len() > 0].reset_index(drop=True)

    # exact-duplicate handling; identical text with conflicting source classes -> kept once, sent to review
    df["_k"] = df.message.map(norm_key)
    df["_pos"] = df.source_kind != "legit"
    conflict = set(df.groupby("_k")._pos.nunique().loc[lambda s: s>1].index)
    df = df.drop_duplicates("_k", keep="first").reset_index(drop=True)
    print(f"rows in: {n0}  after exact dedupe: {len(df)}  (conflicting-source-label texts -> review: {len(conflict)})")

    # labels
    df["_sig"] = df.message.map(signals)
    res = [assign(k, s) for k,s in zip(df.source_kind, df._sig)]
    df["label"], df["label_status"], df["review_hint"] = zip(*res)
    c = df._k.isin(conflict)
    df.loc[c, ["label","label_status","review_hint"]] = ["review","needs_review","conflicting_source_labels"]
    df["auto_signals"] = df._sig.map(",".join)
    df["scam_category"] = np.where(df.label=="legitimate","none", np.where(df.label=="scam", df.scam_category_src.replace("unassigned","OTHER"), "unassigned"))
    df.loc[(df.label=="scam") & (df.scam_category=="OTHER") & df._sig.map(lambda s: "prize" in s), "scam_category"] = "LOTTERY_PRIZE"

    # language audit: declared vs word-list heuristic (skip synthetic: declared by generator prompt)
    det = df.message.map(detect_language)
    indic = df.language.isin(["Hindi","Hinglish"]) | det.isin(["Hindi","Hinglish"])
    dis = (df.language_status=="bundle_declared") & (det != df.language) & indic & ~df.source_quality.isin(NO_SIGNAL_LANG_CHECK)
    df.loc[dis, "language_status"] = "needs_review"
    df.loc[(df.language_status=="bundle_declared") & ~dis, "language_status"] = "declared_and_heuristic_agree"
    df["difficulty"] = "unrated"
    df["script"] = df.message.map(detect_script)
    df["language_detected"] = df.message.map(detect_language)
    df["origin_type"] = df.source.map(ORIGIN)
    assert df.origin_type.notna().all(), "unknown source - add it to ORIGIN"
    bad = (df.source == "hindi_15k_templated") & (df.script != "Devanagari")
    df.loc[df.source == "hindi_15k_templated", "language_status"] = "script_verified_devanagari"
    df.loc[bad, "language_status"] = "needs_review"

    # near-duplicate groups
    df["_grp"] = template_ids(df._k.tolist())
    syn = df.origin_type.isin(SYNTHETIC_ORIGINS).values
    g2 = template_ids(df._k[syn].tolist(), threshold=0.5)
    df.loc[syn, "_grp"] = 10_000_000 + g2                       # looser grouping for generated text (offset keeps ids distinct)
    pref = df.scam_category.map(lambda c: "LEG" if c=="none" else ("REV" if c=="unassigned" else c[:4].upper()))
    df["template_id"] = [f"{p}{g:08d}" for p,g in zip(pref, df._grp)]
    df.insert(0, "message_id", [f"MSG{i+1:06d}" for i in range(len(df))])
    out = df[COLS]; out.to_csv("data/interim/merged_dataset.csv", index=False)

    print(f"merged_dataset.csv written: {len(out)} rows; origin_type: {out.origin_type.value_counts().to_dict()}")

if __name__ == "__main__":
    main()
