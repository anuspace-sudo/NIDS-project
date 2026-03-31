import pickle
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model = pickle.load(open(os.path.join(BASE_DIR, "model.pkl"), "rb"))

# Full KDD / NSL-KDD attack category mapping
DOS_ATTACKS = {
    "back","land","neptune","pod","smurf","teardrop",
    "apache2","mailbomb","processtable","udpstorm","worm"
}
PROBE_ATTACKS = {
    "ipsweep","mscan","nmap","portsweep","saint","satan"
}
R2L_ATTACKS = {
    "ftp_write","guess_passwd","imap","multihop","named",
    "phf","sendmail","snmpattack","snmpguess","spy",
    "warezclient","warezmaster","xlock","xsnoop","httptunnel"
}
U2R_ATTACKS = {
    "buffer_overflow","loadmodule","perl","ps",
    "rootkit","sqlattack","xterm","evasive"
}

# Class index mapping (in case model returns numeric indices)
CLASS_INDEX_MAP = {
    0: "Normal",
    1: "DoS",
    2: "Probe", 
    3: "R2L",
    4: "U2R"
}

def map_attack(p):
    if p is None:
        return "Unknown"

    p_str = str(p).strip()

    # numeric predictions: categorical index output
    try:
        num = float(p_str)
        if num.is_integer():
            idx = int(num)
            if idx in CLASS_INDEX_MAP:
                return CLASS_INDEX_MAP[idx]
    except Exception:
        pass

    p_str_clean = p_str.lower()

    if p_str_clean in DOS_ATTACKS:   return "DoS"
    if p_str_clean in PROBE_ATTACKS: return "Probe"
    if p_str_clean in R2L_ATTACKS:   return "R2L"
    if p_str_clean in U2R_ATTACKS:   return "U2R"
    if p_str_clean == "normal":    return "Normal"

    # Normalized class labels
    if p_str_clean == "dos":  return "DoS"
    if p_str_clean == "probe": return "Probe"
    if p_str_clean == "r2l":  return "R2L"
    if p_str_clean == "u2r":  return "U2R"

    if p_str in ["DoS", "Probe", "R2L", "U2R", "Normal"]:
        return p_str

    return "Unknown"

def severity(a):
    return {
        "DoS":     "High",
        "U2R":     "High",
        "R2L":     "Medium",
        "Probe":   "Low",
        "Unknown": "Medium"
    }.get(a, "-")

def future(a):
    return {
        "DoS":     "DDoS escalation",
        "R2L":     "Account breach",
        "U2R":     "Root compromise",
        "Probe":   "Exploit attempt",
        "Unknown": "Further investigation needed"
    }.get(a, "-")

def predict(df, original):
    preds = model.predict(df)

    results = []
    for i, p in enumerate(preds):
        a = map_attack(p)
        results.append({
            "protocol": original.iloc[i]["protocol_type"],
            "service":  original.iloc[i]["service"],
            "status":   "Attack" if a != "Normal" else "Normal",
            "attack":   a,
            "severity": severity(a),
            "future":   future(a)
        })

    return results, preds
