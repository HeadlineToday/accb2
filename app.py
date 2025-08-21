import os, re, uuid, hashlib, time
from datetime import datetime, timedelta
from pathlib import Path

from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort, send_from_directory, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
from dotenv import load_dotenv
import filetype

from flask_socketio import SocketIO

load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET", "dev")
socketio = SocketIO(app, cors_allowed_origins="*")  # eventlet in production

# --- Mongo ---
client = MongoClient(os.getenv("MONGO_URI"))
db = client[os.getenv("DB_NAME", "anon_app")]
Users = db.users
Posts = db.posts
Banned = db.banned_words
AdminLogs = db.admin_logs

# --- Config ---
POST_COOLDOWN = int(os.getenv("POST_COOLDOWN_SECONDS", "120"))
MAX_IMAGE_MB = int(os.getenv("MAX_IMAGE_MB", "5"))
UPLOAD_DIR = os.getenv("UPLOAD_DIR") or str(Path("uploads").resolve())
Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

# --- Helpers ---
def _iso(dt): return dt.replace(microsecond=0).isoformat()

def current_user():
    anon_id = session.get("anon_id")
    if not anon_id:
        # bootstrap new anon user
        ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "0.0.0.0"
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()
        tag = f"Student{uuid.uuid4().hex[:8]}"
        uid = Users.insert_one({
            "anonymous_tag": tag, "ip_hash": ip_hash, "role": "user",
            "status": "active", "mute_until": None,
            "created_at": datetime.utcnow(), "last_post_at": None,
            "email": None, "password_hash": None
        }).inserted_id
        session["anon_id"] = str(uid)
        session["anon_tag"] = tag
        return Users.find_one({"_id": uid})
    return Users.find_one({"_id": ObjectId(anon_id)})

def require_admin(master_ok=False):
    u = current_user()
    if u.get("role") not in (("master_admin","admin") if master_ok else ("admin","master_admin")):
        abort(403)
    return u

def is_image_ok(fobj, filename):
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT: return False, "Unsupported extension"
    head = fobj.read(261)
    fobj.seek(0)
    kind = filetype.guess(head)
    if not kind or not kind.mime.startswith("image/"): return False, "Invalid image"
    fobj.seek(0)
    fobj.seek(0, os.SEEK_END)
    size_mb = fobj.tell()/1024/1024
    fobj.seek(0)
    if size_mb > MAX_IMAGE_MB: return False, f"Image > {MAX_IMAGE_MB}MB"
    return True, None

def banned_regex():
    words = [re.escape(w["word"]) for w in Banned.find({}, {"word":1})]
    if not words: return None
    return re.compile(r"(?i)\b(" + "|".join(words) + r")\b")

# Seed master admin once
if not Users.find_one({"role":"master_admin"}):
    Users.insert_one({
        "anonymous_tag": "MasterAdmin",
        "ip_hash": "seed",
        "role": "master_admin",
        "status": "active",
        "mute_until": None,
        "created_at": datetime.utcnow(),
        "last_post_at": None,
        "email": os.getenv("ADMIN_EMAIL"),
        "password_hash": generate_password_hash(os.getenv("ADMIN_PASSWORD","admin123"))
    })

# --- Routes ---
@app.route("/")
def index():
    u = current_user()
    posts = list(Posts.find({"status":"active"}).sort("created_at", DESCENDING).limit(100))
    cooldown_left = 0
    if u.get("last_post_at"):
        delta = (datetime.utcnow() - u["last_post_at"]).total_seconds()
        cooldown_left = max(0, POST_COOLDOWN - int(delta))
    return render_template("index.html", posts=posts, user=u,
                           cooldown_left=cooldown_left)

@app.post("/post")
def create_post():
    u = current_user()
    if u["status"] == "banned":
        abort(403)
    if u["mute_until"] and datetime.utcnow() < u["mute_until"]:
        flash("You are muted for now.", "warn")
        return redirect(url_for("index"))

    # cooldown
    if u.get("last_post_at"):
        if (datetime.utcnow() - u["last_post_at"]).total_seconds() < POST_COOLDOWN:
            flash("Please wait before posting again.", "warn")
            return redirect(url_for("index"))

    text = (request.form.get("text") or "").strip()
    image_url = None

    # banned words
    rx = banned_regex()
    if rx and text and rx.search(text):
        flash("Your post contains a banned word.", "error")
        return redirect(url_for("index"))

    file = request.files.get("image")
    if file and file.filename:
        ok, why = is_image_ok(file.stream, file.filename)
        if not ok:
            flash(why, "error")
            return redirect(url_for("index"))
        filename = secure_filename(f"{uuid.uuid4().hex}{Path(file.filename).suffix.lower()}")
        path = Path(UPLOAD_DIR) / filename
        file.save(path)
        image_url = f"/uploads/{filename}"

    if not text and not image_url:
        flash("Post something (text or image).", "error")
        return redirect(url_for("index"))

    doc = {
        "user_id": str(u["_id"]),
        "anonymous_tag": u["anonymous_tag"],
        "text": text or None,
        "image_url": image_url,
        "status": "active",
        "created_at": datetime.utcnow(),
        "likes": 0,
        "liked_by": []
    }
    pid = Posts.insert_one(doc).inserted_id
    Users.update_one({"_id": u["_id"]}, {"$set": {"last_post_at": datetime.utcnow()}})

    payload = {
        "post_id": str(pid),
        "_id": str(pid),
        "anonymous_tag": doc["anonymous_tag"],
        "text": doc["text"],
        "image_url": doc["image_url"],
        "created_at": _iso(doc["created_at"]),
        "status": "active",
        "likes": 0
    }
    socketio.emit("new_post", payload, broadcast=True)
    flash("Posted!", "ok")
    return redirect(url_for("index"))

@app.post("/like/<post_id>")
def like(post_id):
    u = current_user()
    post = Posts.find_one({"_id": ObjectId(post_id)})
    if not post or post["status"] != "active":
        abort(404)
    uid = str(u["_id"])
    if uid in post.get("liked_by", []):
        Posts.update_one({"_id": post["_id"]},
                         {"$pull": {"liked_by": uid}, "$inc": {"likes": -1}})
        liked = False
    else:
        Posts.update_one({"_id": post["_id"]},
                         {"$addToSet": {"liked_by": uid}, "$inc": {"likes": 1}})
        liked = True
    new_count = Posts.find_one({"_id": post["_id"]}, {"likes":1})["likes"]
    socketio.emit("like_update", {
        "post_id": post_id,
        "likes": new_count,
        "user_id": uid,
        "user_tag": u["anonymous_tag"]
    }, broadcast=True)
    return jsonify({"likes": new_count, "liked": liked})

@app.get("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename, conditional=True)

# --- Admin auth (simple) ---
@app.get("/admin/login")
def admin_login_get():
    return render_template("admin_login.html")

@app.post("/admin/login")
def admin_login_post():
    email = request.form.get("email","").strip().lower()
    pw = request.form.get("password","")
    u = Users.find_one({"email": email, "role": {"$in": ["admin","master_admin"]}})
    if not u or not check_password_hash(u["password_hash"], pw):
        flash("Invalid login", "error")
        return redirect(url_for("admin_login_get"))
    session["anon_id"] = str(u["_id"])
    session["anon_tag"] = u["anonymous_tag"]
    flash("Welcome admin", "ok")
    return redirect(url_for("admin"))

@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))

@app.get("/admin")
def admin():
    require_admin()
    posts = list(Posts.find({}).sort("created_at", DESCENDING).limit(200))
    users = list(Users.find({}).sort("created_at", DESCENDING).limit(100))
    words = list(Banned.find({}).sort("added_at", DESCENDING))
    return render_template("admin.html", posts=posts, users=users, words=words)

@app.post("/admin/hide_post")
def admin_hide_post():
    admin_u = require_admin()
    pid = request.form["post_id"]
    Posts.update_one({"_id": ObjectId(pid)}, {"$set": {"status":"hidden"}})
    AdminLogs.insert_one({"admin_id": str(admin_u["_id"]), "action": "hide_post",
                          "target": pid, "extra": None, "at": datetime.utcnow()})
    socketio.emit("post_status_changed", {"post_id": pid, "status":"hidden"}, broadcast=True)
    return redirect(url_for("admin"))

@app.post("/admin/unhide_post")
def admin_unhide_post():
    admin_u = require_admin()
    pid = request.form["post_id"]
    Posts.update_one({"_id": ObjectId(pid)}, {"$set": {"status":"active"}})
    AdminLogs.insert_one({"admin_id": str(admin_u["_id"]), "action": "unhide_post",
                          "target": pid, "extra": None, "at": datetime.utcnow()})
    socketio.emit("post_status_changed", {"post_id": pid, "status":"active"}, broadcast=True)
    return redirect(url_for("admin"))

@app.post("/admin/add_banned_word")
def add_word():
    require_admin()
    w = (request.form.get("word") or "").strip().lower()
    if w:
        Banned.update_one({"word": w}, {"$setOnInsert":{"word":w,"added_at":datetime.utcnow()}}, upsert=True)
    return redirect(url_for("admin"))

@app.post("/admin/remove_banned_word")
def remove_word():
    require_admin()
    wid = request.form["word_id"]
    Banned.delete_one({"_id": ObjectId(wid)})
    return redirect(url_for("admin"))

# --- Run (eventlet ready) ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
