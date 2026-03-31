from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO
from modules.data_collection import load_data
from modules.preprocessing import preprocess
from modules.prediction import predict, map_attack, severity
from modules.reporting import summary

from scapy.all import AsyncSniffer
import sqlite3
import hashlib
import threading
from functools import wraps
from collections import defaultdict
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)
app.secret_key = "nids_cyber_secure_2024"
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

init_db()

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ---------------- AUTH ----------------
@app.route("/")
def index():
    return redirect(url_for('home') if 'user' in session else url_for('login'))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = hash_pw(request.form.get("password",""))

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password))
        user = c.fetchone()
        conn.close()

        if user:
            session['user'] = username
            return redirect(url_for('home'))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error, success=success)

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form.get("username","").strip()
    password = hash_pw(request.form.get("password",""))

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users VALUES (NULL,?,?)",(username,password))
        conn.commit()
        conn.close()
        return render_template("login.html", success="Account created successfully!")
    except:
        return render_template("login.html", error="Username already exists")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------- HOME ----------------
@app.route("/home")
@login_required
def home():
    return render_template("home.html", user=session['user'])

# ---------------- MANUAL ----------------
@app.route("/manual")
@login_required
def manual():
    try:
        df = load_data()
        df_processed, original = preprocess(df)
        results, preds = predict(df_processed, original)
        attack_count, normal_count = summary(preds, map_attack)
    except Exception as ex:
        return render_template("manual.html", results=[], attack_count=0, normal_count=0, total=0,
                               attack_types={"DoS":0,"Probe":0,"R2L":0,"U2R":0,"Normal":0,"Unknown":0},
                               error=str(ex), user=session['user'])

    attack_types = {"DoS":0, "Probe":0, "R2L":0, "U2R":0, "Normal":0, "Unknown":0}

    for r in results:
        attack = r.get("attack", "Unknown")
        if attack in attack_types:
            attack_types[attack] += 1
        else:
            attack_types["Unknown"] += 1

    return render_template("manual.html",
        results=results[:100],
        attack_count=attack_count,
        normal_count=normal_count,
        total=len(results),
        attack_types=attack_types,
        user=session['user']
    )

# ---------------- LIVE DETECTION ----------------
active = {}
sniffer = None
sniffer_lock = threading.Lock()

import time
import threading

traffic_counter = defaultdict(int)
first_seen = {}
last_emit_time = 0
active_lock = threading.Lock()

packet_buffer = []
global_stats = {"total": 0, "attack": 0, "normal": 0, "unique": set()}

def detect_attack_type(count, elapsed):
    """Smarter realistic mapping based on sustained packets per second"""
    # Ignore the first 2 seconds of a connection due to handshake packet bursts
    if elapsed < 2.0:
        return "Normal"
        
    rate = count / elapsed
    if rate > 500:
        return "DoS"
    elif rate > 200:
        return "Probe"
    elif rate > 50:
        return "R2L"
    else:
        return "Normal"

def process_packet(p):
    global sniffer, last_emit_time

    if sniffer is None or not p.haslayer("IP"):
        return

    try:
        src = p["IP"].src
        dst = p["IP"].dst
        key = f"{src} → {dst}"

        now = time.time()
        if key not in first_seen:
            first_seen[key] = now

        traffic_counter[key] += 1
        count = traffic_counter[key]
        
        # Calculate packets per second
        elapsed = now - first_seen[key]
        
        attack_type = detect_attack_type(count, elapsed)

        with active_lock:
            global_stats["total"] += 1
            global_stats["unique"].add(key)
            if attack_type == "Normal":
                global_stats["normal"] += 1
            else:
                global_stats["attack"] += 1

            packet_info = {
                "ip": key,
                "status": "Normal" if attack_type == "Normal" else "Attack",
                "attack": attack_type,
                "severity": "Low" if attack_type == "Normal" else "High",
                "bytes": len(p),
                "rate": round(count / max(elapsed, 0.1), 1)
            }
            packet_buffer.append(packet_info)

        # Throttle websocket emits to 2 times a second for performance
        if now - last_emit_time > 0.5:
            last_emit_time = now
            with active_lock:
                flows = list(packet_buffer)
                packet_buffer.clear()
            
            payload = {
                "total_packets": global_stats["total"],
                "total_unique": len(global_stats["unique"]),
                "total_normal": global_stats["normal"],
                "total_attack": global_stats["attack"],
                "flows": flows
            }
            socketio.emit("update", payload)

    except Exception as e:
        print("Error:", e)

@app.route("/live")
@login_required
def live():
    return render_template("live.html", user=session['user'])

@app.route("/start_sniff", methods=["POST"])
@login_required
def start_sniff():
    global sniffer, packet_buffer, traffic_counter, first_seen, global_stats

    with sniffer_lock:
        if sniffer:
            sniffer.stop()

        packet_buffer.clear()
        traffic_counter.clear()
        first_seen.clear()
        global_stats = {"total": 0, "attack": 0, "normal": 0, "unique": set()}

        sniffer = AsyncSniffer(prn=process_packet, store=False, filter="ip")
        sniffer.start()

    return jsonify({"status":"started"})

@app.route("/stop_sniff", methods=["POST"])
@login_required
def stop_sniff():
    global sniffer, active

    with sniffer_lock:
        if sniffer:
            sniffer.stop()

        sniffer = None
        active = {}

    return jsonify({"status":"stopped"})

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)

