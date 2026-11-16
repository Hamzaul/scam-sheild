import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack

df = pd.read_csv("data/processed/train.csv")

messages = df["message"].fillna("").astype(str)

print("Total messages:", len(messages))

char_vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(2, 5),
    max_features=300000,
    min_df=3,
    sublinear_tf=True
)

X_char = char_vectorizer.fit_transform(messages)

print("\nCHARACTER TF-IDF")
print("Shape:", X_char.shape)


word_vectorizer = TfidfVectorizer(
    analyzer="word",
    ngram_range=(1, 2),
    max_features=150000,
    min_df=2,
    sublinear_tf=True
)

X_word = word_vectorizer.fit_transform(messages)

print("\nWORD TF-IDF")
print("Shape:", X_word.shape)


X_combined = hstack([X_char, X_word]).tocsr()

print("\nCOMBINED TF-IDF")
print("Shape:", X_combined.shape)


print("\nSAMPLE CHARACTER FEATURES")
print(char_vectorizer.get_feature_names_out()[:20])

print("\nSAMPLE WORD FEATURES")
print(word_vectorizer.get_feature_names_out()[:20])

print("\nTF-IDF EXPERIMENT COMPLETED")