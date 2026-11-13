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

RAW = Path("data/raw/public_datasets"); BUNDLE = RAW/"bundle_jsonl"
D_FILE = RAW/"indian_scam_sms_synthetic_audited.csv"
COLS = ["message_id","message","language","label","scam_category","source","difficulty","template_id","original_label",
        "label_status","language_status","source_quality","auto_signals","review_hint","source_id"]
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
    if D_FILE.exists(): parts.append(load_d())
    else: print(f"NOTE: {D_FILE.name} not found - Dataset D NOT included.")
    df = pd.concat(parts, ignore_index=True)
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

    # near-duplicate groups
    df["_grp"] = template_ids(df._k.tolist())
    pref = df.scam_category.map(lambda c: "LEG" if c=="none" else ("REV" if c=="unassigned" else c[:4].upper()))
    df["template_id"] = [f"{p}{g:06d}" for p,g in zip(pref, df._grp)]
    df.insert(0, "message_id", [f"MSG{i+1:06d}" for i in range(len(df))])
    out = df[COLS]; out.to_csv("data/interim/merged_dataset.csv", index=False)

    # ---------- splits
    reserved_groups = set(df[df.source.isin(RESERVED_SOURCES)]._grp)
    reserved = df[df._grp.isin(reserved_groups)]
    reserved[COLS].to_csv("data/processed/heldout_benchmark_candidates.csv", index=False)
    ok = df[df.label.isin(["scam","legitimate"]) & ~df._grp.isin(reserved_groups)].reset_index(drop=True)
    grp_ok = ok.groupby("_grp").source_quality.apply(lambda s: set(s) <= TEST_OK_QUALITY)
    ok["_test_ok"] = ok._grp.map(grp_ok)
    assign_s = pd.Series(index=ok.index, dtype=object)
    def split(sub, mapper, n):
        f = StratifiedGroupKFold(n_splits=n, shuffle=True, random_state=SEED)
        for k,(_,idx) in enumerate(f.split(sub, (sub.label=="scam").astype(int), sub._grp)): assign_s[sub.index[idx]] = mapper(k)
    split(ok[ok._test_ok],  lambda k: "train" if k<14 else ("validation" if k<17 else "test"), 20)
    split(ok[~ok._test_ok], lambda k: "validation" if k==0 else "train", 7)
    for name in ["train","validation","test"]:
        p = ok[assign_s==name]; p[COLS].to_csv(f"data/processed/{name}.csv", index=False)
        print(f"{name:10s} n={len(p):6d} scam%={100*(p.label=='scam').mean():5.1f}  {p.language.value_counts().to_dict()}")
    S = [set(ok[assign_s==n]._grp) for n in ["train","validation","test"]]
    assert not (S[0]&S[1] or S[0]&S[2] or S[1]&S[2]), "template leakage!"
    assert not (set(ok._grp) & reserved_groups), "reserved benchmark leaked into splits"
    print("leakage check passed: no near-duplicate group shared across splits or with the reserved benchmark")

    # ---------- review queue (prioritised; samples carry stratum size so proportions can be estimated)
    rng = np.random.RandomState(SEED)
    def mk(sub, qtype, pri, extra=""):
        sub = sub.copy(); sub["queue_type"], sub["priority"], sub["stratum_size"] = qtype, pri, len(sub); return sub
    parts_q = [mk(reserved, "full_benchmark", 1),
               mk(df[(df.review_hint=="source_legit_but_scam_signals") & ~df._grp.isin(reserved_groups)], "full_legit_with_signals", 2),
               mk(df[(df.label_status=="provisional_auto") & ~df._grp.isin(reserved_groups)], "full_provisional_auto", 3),
               mk(df[(df.review_hint=="conflicting_source_labels")], "full_conflict", 2),
               mk(df[(df.language_status=="needs_review") | (df.language_status=="heuristic_unreviewed")], "full_language_check", 4)]
    for hint, n, pri in [("spam_or_unclear_likely_promo",500,5), ("source_fraud_label_without_definition_signals",400,5)]:
        pool = df[(df.review_hint==hint)]; take = pool.sample(min(n,len(pool)), random_state=SEED)
        parts_q.append(mk(take, f"sample_{hint}", pri).assign(stratum_size=len(pool)))
    q = pd.concat(parts_q).drop_duplicates("message_id")
    q = q[["message_id","message","source","label","language","auto_signals","review_hint","original_label","queue_type","priority","stratum_size"]]
    q = q.rename(columns={"label":"current_label","language":"current_language"}).sort_values(["priority","queue_type"])
    for c in ["reviewer_label","reviewer_language","reviewer_category","reviewer_notes"]: q[c] = ""
    q.to_csv("data/interim/review_queue.csv", index=False)
    print("review queue:", q.queue_type.value_counts().to_dict())

    # ---------- audit report
    usable = out[out.label.isin(["scam","legitimate"])]
    rep = ["# Dataset audit report (auto-generated by scripts/build_dataset.py)\n",
        f"Rows: **{len(out)}** after exact dedupe (from {n0}). Resolved labels (scam/legitimate): **{len(usable)}**. `review`: **{(out.label=='review').sum()}**.\n",
        "## Label x label_status\n", pd.crosstab(out.label, out.label_status).to_markdown(), "\n",
        "## Source x label\n", pd.crosstab(out.source, out.label, margins=True).to_markdown(), "\n",
        "## Language x label (all rows)\n", pd.crosstab(out.language, out.label, margins=True).to_markdown(), "\n",
        "## Language x label (resolved rows only)\n", pd.crosstab(usable.language, usable.label, margins=True).to_markdown(), "\n",
        "## Language status\n", out.language_status.value_counts().to_markdown(), "\n",
        "## review_hint\n", out[out.review_hint!=""].review_hint.value_counts().to_markdown(), "\n",
        "## Source quality x language (resolved rows)\n", pd.crosstab(usable.source_quality, usable.language).to_markdown(), "\n"]
    Path("docs/audit_report.md").write_text("\n".join(rep), encoding="utf-8")

if __name__ == "__main__":
    main()
