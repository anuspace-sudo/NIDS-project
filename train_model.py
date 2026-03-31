import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

columns_kdd = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes",
"land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

df = pd.read_csv("KDDTrain+.txt", names=columns_kdd)

attack_map = {
    'normal':'Normal',
    'neptune':'DoS','smurf':'DoS','back':'DoS','teardrop':'DoS','pod':'DoS',
    'guess_passwd':'R2L','ftp_write':'R2L','imap':'R2L','phf':'R2L',
    'multihop':'R2L','warezmaster':'R2L','warezclient':'R2L','spy':'R2L',
    'buffer_overflow':'U2R','loadmodule':'U2R','rootkit':'U2R','perl':'U2R',
    'satan':'Probe','ipsweep':'Probe','nmap':'Probe','portsweep':'Probe','mscan':'Probe'
}

df["label"] = df["label"].str.strip().apply(lambda x: attack_map.get(x, "Normal"))

normal = df[df["label"] == "Normal"]
attack = df[df["label"] != "Normal"]

if len(attack) == 0:
    print("❌ No attack data found!")
    exit(1)

attack_up = attack.sample(n=len(normal), replace=True, random_state=42)
df = pd.concat([normal, attack_up])

X = df.drop(["label", "difficulty"], axis=1)
y = df["label"]

X = pd.get_dummies(X)
X.columns = X.columns.astype(str)

pickle.dump(X.columns, open("columns.pkl", "wb"))

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

pickle.dump(model, open("model.pkl", "wb"))
print("✅ Model trained successfully!")