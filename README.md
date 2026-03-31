# 🛡️ NIDS — Network Intrusion Detection System

A machine learning-powered web application that detects network intrusions using the NSL-KDD dataset. Built with Flask, Flask-SocketIO, Scapy, and a Random Forest classifier.

---

## 📌 What This Project Does

This application provides two modes of network intrusion detection:

- **Manual Analysis** — Loads the KDD Test dataset (`KDDTest+.txt`), runs it through a trained Random Forest ML model, and classifies each record as Normal or one of four attack types: DoS, Probe, R2L, or U2R.
- **Live Detection** — Uses Scapy to sniff real network packets in real time and flags suspicious traffic via WebSocket live stream. *(Requires local machine with admin/root privileges — does not work on cloud platforms.)*

---

## 🗂️ Project Structure

```
P/
├── app.py                  # Main Flask application — routes, auth, live sniffing
├── train_model.py          # Trains Random Forest on KDDTrain+.txt, saves model.pkl and columns.pkl
├── requirements.txt        # Python dependencies
├── KDDTrain+.txt           # NSL-KDD training dataset (125,973 records)
├── KDDTest+.txt            # NSL-KDD test dataset (22,544 records)
├── modules/
│   ├── data_collection.py  # Loads KDDTest+.txt with correct 41 column names
│   ├── preprocessing.py    # One-hot encodes features, aligns columns using columns.pkl
│   ├── prediction.py       # Loads model.pkl, maps predictions to attack categories
│   └── reporting.py        # Counts attack vs normal predictions
├── templates/
│   ├── login.html          # Login page
│   ├── home.html           # Home — choose Manual or Live mode
│   ├── manual.html         # Manual analysis results page
│   ├── live.html           # Live detection dashboard
│   ├── signup.html
│   ├── dashboard.html
│   ├── result.html
│   └── index.html
└── static/
    ├── style.css           # Global styles
    └── chart.js            # Chart logic for manual analysis page
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask 3.0.3 |
| Real-time | Flask-SocketIO 5.3.6, eventlet 0.36.1 |
| ML Model | scikit-learn 1.4.2 — RandomForestClassifier |
| Data | pandas 2.2.2, numpy 1.26.4 |
| Packet Sniffing | Scapy 2.5.0 |
| Database | SQLite (users.db) |
| Frontend | HTML, CSS, JavaScript, WebSocket |

---

## 🧠 Machine Learning Details

- **Algorithm**: Random Forest Classifier (`n_estimators=100`)
- **Training Data**: NSL-KDD Train+ dataset (`KDDTrain+.txt`) — 125,973 records with 41 features
- **Test Data**: NSL-KDD Test+ dataset (`KDDTest+.txt`) — 22,544 records
- **Features**: 41 KDD features including duration, protocol_type, service, flag, src_bytes, dst_bytes, and 35 others
- **Classes**: Normal, DoS, Probe, R2L, U2R
- **Preprocessing**: One-hot encoding of categorical features (protocol_type, service, flag), column alignment using saved `columns.pkl`
- **Class Balancing**: Attack samples are upsampled to match Normal sample count using `random_state=42`

### Attack Categories Detected

| Category | Example Attacks |
|---|---|
| **DoS** (Denial of Service) | neptune, smurf, back, teardrop, pod |
| **Probe** (Surveillance) | ipsweep, nmap, portsweep, satan, mscan |
| **R2L** (Remote to Local) | guess_passwd, ftp_write, imap, warezmaster |
| **U2R** (User to Root) | buffer_overflow, rootkit, loadmodule, perl |

---

## 🚀 How to Run Locally

### Prerequisites

- Python 3.10 or above
- On Windows: [Npcap](https://npcap.com/) installed (required for Scapy packet sniffing)
- Run as Administrator (required for Scapy live sniffing)

### Step 1 — Clone the repository

```bash
git clone https://github.com/anuspace-sudo/NIDS-project.git
cd NIDS-project
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Train the model

```bash
python train_model.py
```

This reads `KDDTrain+.txt`, trains the Random Forest, and saves `model.pkl` and `columns.pkl` in the project folder.

### Step 4 — Run the app

```bash
python app.py
```

### Step 5 — Open in browser

```
http://localhost:5000
```

Sign up for an account, then log in to access the dashboard.

---

## ☁️ Deployment on Render.com

The Manual Analysis feature is fully deployable on Render's free tier. Live Detection requires local execution (see note below).

### Build Command
```
pip install -r requirements.txt && python train_model.py
```

### Start Command
```
python app.py
```

Render will automatically install all dependencies, retrain the model from `KDDTrain+.txt`, and start the Flask app. Build time is approximately 10–15 minutes due to Random Forest training.

---

## ⚠️ Important Notes

### Live Detection Limitation
The Live Detection feature uses Scapy's `AsyncSniffer` to capture raw network packets. This requires:
- Root or Administrator privileges on the machine
- A physical network interface
- `libpcap` (Linux/Mac) or `Npcap` (Windows) installed at OS level

**Cloud platforms (Render, Heroku, Railway) block raw socket access.** Live Detection only works when running the app locally on your own machine as Administrator.

### Free Tier Sleep
On Render's free plan, the app goes to sleep after 15 minutes of inactivity. The first request after sleep takes 30–50 seconds to respond. This is normal behaviour.

---

## 🔐 Authentication

- User accounts are stored in a local SQLite database (`users.db`)
- Passwords are hashed using SHA-256 before storage
- All routes except `/login` and `/signup` require authentication
- Sessions are managed using Flask's built-in session system

---

## 📁 Files NOT in the Repository

These files are excluded from git (listed in `.gitignore`) and are generated automatically:

| File | How it is generated |
|---|---|
| `model.pkl` | Running `python train_model.py` |
| `columns.pkl` | Running `python train_model.py` |
| `scaler.pkl` | Not used in current code |
| `users.db` | Auto-created on first run of `app.py` |
| `__pycache__/` | Auto-created by Python |
| `.venv/` | Virtual environment — not part of project code |

---

## 📊 Dataset

This project uses the **NSL-KDD dataset**, an improved version of the original KDD Cup 1999 dataset.

- Source: Canadian Institute for Cybersecurity
- Training set: 125,973 records
- Test set: 22,544 records
- Features: 41 network connection features + 1 label column

---

## 👩‍💻 Author

Developed as an academic project demonstrating machine learning-based network intrusion detection with a real-time web interface.
