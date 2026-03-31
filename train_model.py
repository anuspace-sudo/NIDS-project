import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

# ---------------- LOAD DATA ----------------
cols = [i for i in range(43)]
df = pd.read_csv("KDDTrain+.txt", names=cols)

# ---------------- ATTACK MAPPING ----------------
attack_map = {
    'normal': 'Normal',

    'neptune': 'DoS','smurf':'DoS','back':'DoS','teardrop':'DoS','pod':'DoS',

    'guess_passwd':'R2L','ftp_write':'R2L','imap':'R2L','phf':'R2L',
    'multihop':'R2L','warezmaster':'R2L','warezclient':'R2L','spy':'R2L',

    'buffer_overflow':'U2R','loadmodule':'U2R','rootkit':'U2R','perl':'U2R',

    'satan':'Probe','ipsweep':'Probe','nmap':'Probe','portsweep':'Probe','mscan':'Probe'
}

# SAFE mapping
df[41] = df[41].str.strip().apply(lambda x: attack_map.get(x, "Normal"))
# ---------------- BALANCE DATA ----------------
normal = df[df[41] == 'Normal']
attack = df[df[41] != 'Normal']

if len(attack) == 0:
    print("❌ No attack data found!")
    exit()

attack_up = attack.sample(n=len(normal), replace=True, random_state=42)

df = pd.concat([normal, attack_up])

# ---------------- FEATURES ----------------
X = df.drop(41, axis=1)
y = df[41]

# One-hot encoding
X = pd.get_dummies(X)

# Save columns
pickle.dump(X.columns, open("columns.pkl", "wb"))

# ---------------- TRAIN MODEL ----------------

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

pickle.dump(model, open("model.pkl", "wb"))

print("✅ Model trained successfully!")