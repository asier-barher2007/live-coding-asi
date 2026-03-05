import os
import re
import sqlite3
import datetime
import logging
from functools import wraps
from pathlib import Path

import bcrypt
import bleach
import jwt
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
JWT_SECRET  = os.getenv("JWT_SECRET", "f1store_secret_2025")
JWT_EXPIRES = datetime.timedelta(hours=8)
BCRYPT_COST = 12
ALLOWED_CATEGORIES = {"casco", "ropa", "modelo", "accesorios", "coleccionable"}

# La BD se guarda en /app/data/ (mapeado como volumen Docker)
DB_DIR  = Path("/app/data")
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DB_DIR / "f1store.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("f1store")

# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"]         = JWT_SECRET
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024  # 50 KB

# CORS abierto: nginx ya filtra por origen
CORS(app, resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Cabeceras de seguridad
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "SAMEORIGIN"
    return resp

# Rate limiting
limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["300 per 15 minutes"],
                  storage_uri="memory://")

# ─────────────────────────────────────────────
#  BASE DE DATOS
# ─────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password   TEXT    NOT NULL,
            balance    REAL    NOT NULL DEFAULT 1000.00,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            description TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            price       REAL    NOT NULL,
            image_url   TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS orders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            buyer_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            product_id  INTEGER NOT NULL REFERENCES products(id),
            quantity    INTEGER NOT NULL DEFAULT 1,
            total_price REAL    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()

# ─────────────────────────────────────────────
#  VALIDADORES
# ─────────────────────────────────────────────
class V(Exception):
    def __init__(self, msg):
        self.msg = msg

def clean(v, mn=1, mx=500, name="campo"):
    if not v or not isinstance(v, str):
        raise V(f"El campo '{name}' es obligatorio.")
    s = bleach.clean(v.strip(), tags=[], strip=True)
    if len(s) < mn:
        raise V(f"'{name}' debe tener al menos {mn} caracteres.")
    if len(s) > mx:
        raise V(f"'{name}' no puede superar {mx} caracteres.")
    return s

def val_email(e):
    e = clean(e, mx=254, name="email")
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", e):
        raise V("Email no válido.")
    return e.lower()

def val_username(u):
    u = clean(u, mn=3, mx=30, name="username")
    if not re.match(r"^[a-zA-Z0-9_]+$", u):
        raise V("Username: solo letras, números y guión bajo.")
    return u

def val_password(p):
    if not p or not isinstance(p, str):
        raise V("La contraseña es obligatoria.")
    if len(p) < 8:
        raise V("La contraseña debe tener al menos 8 caracteres.")
    if len(p) > 128:
        raise V("La contraseña no puede superar 128 caracteres.")
    if not re.search(r"[A-Z]", p): raise V("Necesita al menos una mayúscula.")
    if not re.search(r"[a-z]", p): raise V("Necesita al menos una minúscula.")
    if not re.search(r"[0-9]", p): raise V("Necesita al menos un número.")
    if not re.search(r"[^a-zA-Z0-9]", p): raise V("Necesita al menos un símbolo (!, @, #…).")
    return p

def val_price(p):
    try:
        v = float(p)
    except (TypeError, ValueError):
        raise V("Precio no válido.")
    if v <= 0 or v > 99999:
        raise V("Precio fuera de rango (0.01 – 99999).")
    return round(v, 2)

def val_url(u):
    if not u:
        return None
    u = str(u).strip()
    if not re.match(r"^https://", u, re.I):
        raise V("La URL de imagen debe empezar con https://")
    if len(u) > 2048:
        raise V("URL demasiado larga.")
    return u

# ─────────────────────────────────────────────
#  JWT / AUTH
# ─────────────────────────────────────────────
def make_token(uid):
    return jwt.encode(
        {"id": uid,
         "exp": datetime.datetime.utcnow() + JWT_EXPIRES,
         "iat": datetime.datetime.utcnow()},
        JWT_SECRET, algorithm="HS256"
    )

def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return jsonify({"message": "No autorizado."}), 401
        try:
            pay = jwt.decode(h[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Sesión expirada."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token inválido."}), 401
        user = get_db().execute(
            "SELECT id,username,email,balance FROM users WHERE id=?", (pay["id"],)
        ).fetchone()
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 401
        g.user = dict(user)
        return f(*a, **kw)
    return wrapper

def pub(u):
    return {k: u[k] for k in ("id","username","email","balance")}

# ─────────────────────────────────────────────
#  ERRORES GLOBALES
# ─────────────────────────────────────────────
@app.errorhandler(404)
def e404(_): return jsonify({"message": "Ruta no encontrada."}), 404

@app.errorhandler(405)
def e405(_): return jsonify({"message": "Método no permitido."}), 405

@app.errorhandler(413)
def e413(_): return jsonify({"message": "Petición demasiado grande."}), 413

@app.errorhandler(429)
def e429(_): return jsonify({"message": "Demasiados intentos. Espera un momento."}), 429

@app.errorhandler(Exception)
def e500(err):
    logger.error("Error inesperado: %s", repr(err))
    return jsonify({"message": "Error interno del servidor."}), 500

# ─────────────────────────────────────────────
#  RUTAS — HEALTH
# ─────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"ok": True}), 200

# ─────────────────────────────────────────────
#  RUTAS — AUTH
# ─────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def register():
    d = request.get_json(silent=True) or {}
    try:
        username = val_username(d.get("username"))
        email    = val_email(d.get("email"))
        password = val_password(d.get("password"))
    except V as e:
        return jsonify({"message": e.msg}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=? OR username=?",
                  (email, username)).fetchone():
        return jsonify({"message": "Email o username ya registrado."}), 409

    pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(BCRYPT_COST)).decode()
    cur = db.execute(
        "INSERT INTO users (username,email,password) VALUES (?,?,?)",
        (username, email, pw)
    )
    db.commit()
    user = db.execute("SELECT id,username,email,balance FROM users WHERE id=?",
                      (cur.lastrowid,)).fetchone()
    logger.info("Nuevo usuario: %s", email)
    return jsonify({"token": make_token(user["id"]), "user": pub(user)}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).lower().strip()
    pw    = str(d.get("password", ""))

    if not email or not pw:
        return jsonify({"message": "Email y contraseña son obligatorios."}), 400
    if len(email) > 254 or len(pw) > 128:
        return jsonify({"message": "Credenciales incorrectas."}), 401

    user  = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    dummy = "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    stored = user["password"] if user else dummy
    try:
        ok = bcrypt.checkpw(pw.encode(), stored.encode())
    except Exception:
        ok = False

    if not user or not ok:
        return jsonify({"message": "Credenciales incorrectas."}), 401
    return jsonify({"token": make_token(user["id"]), "user": pub(dict(user))}), 200

# ─────────────────────────────────────────────
#  RUTAS — PRODUCTOS
# ─────────────────────────────────────────────
@app.route("/api/products")
def get_products():
    db = get_db()
    search   = str(request.args.get("search","")).strip()[:100]
    category = str(request.args.get("category","")).strip()
    sort     = str(request.args.get("sort","newest")).strip()

    q = """SELECT p.*,u.username AS seller_username
           FROM products p JOIN users u ON u.id=p.seller_id WHERE 1=1"""
    params = []
    if search:
        s = bleach.clean(search, tags=[], strip=True)
        q += " AND (p.name LIKE ? OR p.description LIKE ?)"
        params += [f"%{s}%", f"%{s}%"]
    if category in ALLOWED_CATEGORIES:
        q += " AND p.category=?"
        params.append(category)
    q += " ORDER BY " + {
        "newest": "p.created_at DESC",
        "price-asc": "p.price ASC",
        "price-desc": "p.price DESC"
    }.get(sort, "p.created_at DESC")

    return jsonify({"products": [dict(r) for r in db.execute(q, params)]}), 200


@app.route("/api/products/my")
@require_auth
def my_products():
    rows = get_db().execute(
        "SELECT * FROM products WHERE seller_id=? ORDER BY created_at DESC",
        (g.user["id"],)
    ).fetchall()
    return jsonify({"products": [dict(r) for r in rows]}), 200


@app.route("/api/products", methods=["POST"])
@require_auth
@limiter.limit("30 per hour")
def create_product():
    d = request.get_json(silent=True) or {}
    try:
        name  = clean(d.get("name"), mn=3, mx=100, name="nombre")
        desc  = clean(d.get("description"), mn=10, mx=500, name="descripción")
        cat   = str(d.get("category","")).strip()
        price = val_price(d.get("price"))
        url   = val_url(d.get("image_url"))
    except V as e:
        return jsonify({"message": e.msg}), 400
    if cat not in ALLOWED_CATEGORIES:
        return jsonify({"message": "Categoría no válida."}), 400
    db  = get_db()
    cur = db.execute(
        "INSERT INTO products (seller_id,name,description,category,price,image_url) VALUES (?,?,?,?,?,?)",
        (g.user["id"], name, desc, cat, price, url)
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "message": "Producto publicado."}), 201


@app.route("/api/products/<int:pid>", methods=["PUT"])
@require_auth
def update_product(pid):
    db = get_db()
    p  = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p: return jsonify({"message": "No encontrado."}), 404
    if p["seller_id"] != g.user["id"]:
        return jsonify({"message": "Sin permiso."}), 403
    d = request.get_json(silent=True) or {}
    try:
        name  = clean(d.get("name"), mn=3, mx=100, name="nombre")
        desc  = clean(d.get("description"), mn=10, mx=500, name="descripción")
        cat   = str(d.get("category","")).strip()
        price = val_price(d.get("price"))
        url   = val_url(d.get("image_url"))
    except V as e:
        return jsonify({"message": e.msg}), 400
    if cat not in ALLOWED_CATEGORIES:
        return jsonify({"message": "Categoría no válida."}), 400
    db.execute(
        "UPDATE products SET name=?,description=?,category=?,price=?,image_url=? WHERE id=?",
        (name, desc, cat, price, url, pid)
    )
    db.commit()
    return jsonify({"message": "Actualizado."}), 200


@app.route("/api/products/<int:pid>", methods=["DELETE"])
@require_auth
def delete_product(pid):
    db = get_db()
    p  = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p: return jsonify({"message": "No encontrado."}), 404
    if p["seller_id"] != g.user["id"]:
        return jsonify({"message": "Sin permiso."}), 403
    db.execute("DELETE FROM products WHERE id=?", (pid,))
    db.commit()
    return jsonify({"message": "Eliminado."}), 200

# ─────────────────────────────────────────────
#  RUTAS — PEDIDOS
# ─────────────────────────────────────────────
@app.route("/api/orders", methods=["POST"])
@require_auth
@limiter.limit("50 per hour")
def create_order():
    items = (request.get_json(silent=True) or {}).get("items", [])
    if not items or not isinstance(items, list):
        return jsonify({"message": "Carrito vacío."}), 400
    if len(items) > 50:
        return jsonify({"message": "Demasiados productos."}), 400
    db = get_db()
    try:
        for item in items:
            pid = int(item.get("product_id", 0))
            qty = int(item.get("quantity", 0))
            if pid <= 0 or qty <= 0 or qty > 100:
                return jsonify({"message": "Cantidad inválida."}), 400
            p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
            if not p: return jsonify({"message": f"Producto {pid} no encontrado."}), 404
            if p["seller_id"] == g.user["id"]:
                return jsonify({"message": "No puedes comprar tus propios productos."}), 400
            total = round(p["price"] * qty, 2)
            db.execute("INSERT INTO orders (buyer_id,product_id,quantity,total_price) VALUES (?,?,?,?)",
                       (g.user["id"], pid, qty, total))
            db.execute("UPDATE users SET balance=balance-? WHERE id=?", (total, g.user["id"]))
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (total, p["seller_id"]))

        buyer = db.execute("SELECT balance FROM users WHERE id=?", (g.user["id"],)).fetchone()
        if buyer["balance"] < 0:
            db.rollback()
            return jsonify({"message": "Saldo insuficiente."}), 400
        db.commit()
        return jsonify({"message": "Compra realizada.", "new_balance": buyer["balance"]}), 201
    except Exception as e:
        db.rollback()
        logger.error("checkout error: %s", e)
        return jsonify({"message": "Error al procesar la compra."}), 500


@app.route("/api/orders/my")
@require_auth
def my_orders():
    rows = get_db().execute("""
        SELECT o.id,o.quantity,o.total_price,o.created_at,
               p.name AS product_name, p.category AS product_category,
               p.image_url AS product_image
        FROM orders o JOIN products p ON p.id=o.product_id
        WHERE o.buyer_id=? ORDER BY o.created_at DESC
    """, (g.user["id"],)).fetchall()
    return jsonify({"orders": [dict(r) for r in rows]}), 200

# ─────────────────────────────────────────────
#  ARRANQUE — funciona con `flask run` Y con `python app.py`
#  init_db() está al nivel del módulo → se ejecuta siempre
# ─────────────────────────────────────────────
try:
    init_db()
    from seed import run_seed
    run_seed(DB_PATH)
    logger.info("✅ BD lista: %s", DB_PATH)
except Exception as e:
    logger.error("⚠️  Error en arranque: %s", e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)