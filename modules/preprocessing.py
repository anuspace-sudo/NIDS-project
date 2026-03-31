import pandas as pd
import pickle
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
columns = pickle.load(open(os.path.join(BASE_DIR, "columns.pkl"), "rb"))

def preprocess(df):
    original = df.copy()
    df = df.drop(["label", "difficulty"], axis=1, errors="ignore")
    df = pd.get_dummies(df)
    df = df.reindex(columns=columns, fill_value=0)
    return df, original