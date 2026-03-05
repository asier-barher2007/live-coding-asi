"""
F1 STORE — seed.py
Productos reales de las tiendas oficiales de F1:
  - F1 Official Store (formula1.com)
  - McLaren Official Store (store.mclaren.com)
  - Fueler Store (fueler.store)
  - F1 Authentics (f1authentics.com)
Precios convertidos a EUR (aproximado). Imágenes de Unsplash (uso libre).
"""

import sqlite3
import bcrypt
import logging

logger = logging.getLogger("f1store.seed")

# ──────────────────────────────────────────────────────────────
STORE_USER = {
    "username": "f1store_oficial",
    "email":    "oficial@f1store.com",
    "password": "F1store@2025!",
    "balance":  99999.00,
}

# ──────────────────────────────────────────────────────────────
#  PRODUCTOS REALES — fuentes: formula1.com, store.mclaren.com,
#  fueler.store, f1authentics.com  (precios en EUR aprox.)
# ──────────────────────────────────────────────────────────────
PRODUCTS = [

    # ════════════════════════════════
    #  CASCOS
    # ════════════════════════════════
    {
        "category":    "casco",
        "name":        "Casco Réplica 1:2 Lando Norris 2025 McLaren",
        "description": "Réplica oficial a escala 1:2 del casco de Lando Norris para la temporada 2025 de McLaren Racing. Fabricado en fibra de vidrio con acabados en color papaya y azul marino. Incluye soporte de exposición y certificado de autenticidad. Producto oficial McLaren Racing Store.",
        "price":       211.99,
        "image_url":   "https://images.unsplash.com/photo-1618897996318-5a901fa6ca71?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "casco",
        "name":        "Mini Casco Leclerc GP Singapur 2024 — 1:5 Ferrari",
        "description": "Mini casco oficial escala 1:5 de Charles Leclerc del Gran Premio de Singapur 2024. Edición limitada Scuderia Ferrari con los colores rojo Ferrari y el número 16. Incluye caja de presentación con ventana. Precio oficial Fueler Store: $110.",
        "price":       101.00,
        "image_url":   "https://images.unsplash.com/photo-1504215680853-026ed2a45def?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "casco",
        "name":        "Réplica 1:2 Oscar Piastri Australia GP 2026",
        "description": "Réplica a escala 1:2 del casco de Oscar Piastri para el Gran Premio de Australia 2026. Diseño exclusivo del piloto australiano de McLaren en color papaya con detalles verdes. Disponible en pre-order. Precio oficial Oscar Piastri Store: $229.99.",
        "price":       211.00,
        "image_url":   "https://images.unsplash.com/photo-1580274455191-1c62238fa333?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "casco",
        "name":        "Mini Casco Michael Schumacher 1991 — Edición Mini",
        "description": "Mini casco réplica de Michael Schumacher de su primera temporada en F1, 1991. Pieza de coleccionista con el diseño original del legendario piloto alemán. Producto oficial Fueler Store, precio original $30.",
        "price":       27.50,
        "image_url":   "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=600&h=600&fit=crop&q=85",
    },

    # ════════════════════════════════
    #  ROPA
    # ════════════════════════════════
    {
        "category":    "ropa",
        "name":        "Camiseta McLaren 2026 Team Set Up — Papaya",
        "description": "Camiseta oficial del equipo McLaren Mastercard F1 para la temporada 2026. Color papaya con manga corta y el logo del equipo en el pecho. Tejido técnico transpirable Castore con ajuste regular. Precio oficial McLaren Store: $96.",
        "price":       88.00,
        "image_url":   "https://images.unsplash.com/photo-1562157873-818bc0726f68?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "ropa",
        "name":        "Hoodie McLaren 2025 Team — Negro",
        "description": "Sudadera oficial con capucha McLaren Racing 2025 en color negro con detalles papaya. Bolsillo canguro, cordones a juego y logos del equipo bordados. Material: mezcla algodón-poliéster. Precio oficial McLaren Essential Store: $79.",
        "price":       73.00,
        "image_url":   "https://images.unsplash.com/photo-1556821840-3a63f15732ce?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "ropa",
        "name":        "Chaqueta Softshell McLaren 2026 — Unisex",
        "description": "Chaqueta softshell oficial McLaren Racing 2026 para hombre y mujer. Exterior resistente al viento con forro transpirable interior. Cremallera completa, bolsillos con zip y el logo papaya McLaren. Precio oficial McLaren Store: $216.",
        "price":       198.00,
        "image_url":   "https://images.unsplash.com/photo-1591047139829-d91aecb6caea?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "ropa",
        "name":        "Polo Red Bull Racing 2025 Team — Castore",
        "description": "Polo técnico oficial Red Bull Racing temporada 2025 fabricado por Castore. Tejido de alto rendimiento transpirable con el logo Oracle Red Bull Racing bordado en el pecho y mangas con detalle en azul marino. Precio oficial Fueler Store: $105 (antes $125).",
        "price":       97.00,
        "image_url":   "https://images.unsplash.com/photo-1618354691373-d851c5c3a990?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "ropa",
        "name":        "Hoodie Aston Martin F1 2025 — Stealth Logo",
        "description": "Sudadera Stealth Logo oficial del equipo Aston Martin F1 en color verde Racing con logo de tono sobre tono. Diseño minimalista premium con acabados de alta calidad. Tejido suave y resistente. Precio oficial Fueler Store: $115.",
        "price":       105.00,
        "image_url":   "https://images.unsplash.com/photo-1618354691592-d51a0e8b9a5a?w=600&h=600&fit=crop&q=85",
    },

    # ════════════════════════════════
    #  MODELOS A ESCALA
    # ════════════════════════════════
    {
        "category":    "modelo",
        "name":        "Ferrari SF24 LEGO Technic 1:18 — Set Oficial",
        "description": "Set LEGO Technic del Ferrari SF24 a escala 1:18 con licencia oficial Scuderia Ferrari. Más de 1.400 piezas con suspensión funcional, alerón trasero con DRS y volante extraíble. Precio oficial Fueler Store: $395.",
        "price":       362.00,
        "image_url":   "https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "modelo",
        "name":        "Ferrari SF-23 Hamilton Fiorano 2025 — Bburago 1:18",
        "description": "Modelo oficial Bburago a escala 1:18 del Ferrari SF-23 de Lewis Hamilton en los test de Fiorano 2025. Primera temporada de Hamilton con Ferrari. Carrocería roja con el número 44. Precio oficial Fueler Store: $130.",
        "price":       119.00,
        "image_url":   "https://images.unsplash.com/photo-1492144534655-ae79c964c9d7?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "modelo",
        "name":        "Ferrari SF24 Leclerc GP Miami 2024 — Amalgam 1:18",
        "description": "Modelo de coleccionista ultra premium Amalgam Collection a escala 1:18 del Ferrari SF24 de Charles Leclerc en el GP de Miami 2024. Fabricado artesanalmente con más de 500 piezas. Precio oficial Fueler Store: $1,990.",
        "price":       1829.00,
        "image_url":   "https://images.unsplash.com/photo-1544636331-e26879cd4d9b?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "modelo",
        "name":        "Leclerc SF24 2024 Season — Die-Cast 1:24",
        "description": "Modelo die-cast oficial a escala 1:24 del Ferrari SF24 de Leclerc temporada 2024. Metal fundido a presión con detalles del habitáculo, alerón con DRS representado y neumáticos de goma. Precio oficial Fueler Store: $50.",
        "price":       46.00,
        "image_url":   "https://images.unsplash.com/photo-1566464252-83a9a5b29e25?w=600&h=600&fit=crop&q=85",
    },

    # ════════════════════════════════
    #  ACCESORIOS
    # ════════════════════════════════
    {
        "category":    "accesorios",
        "name":        "Gorra McLaren New Era 9FIFTY Essentials — Papaya/Negro",
        "description": "Gorra snapback oficial McLaren Racing fabricada por New Era. Visera pre-curva con el logo MCL bordado, cierre trasero snapback ajustable. Colores papaya y negro. Precio oficial F1 Store: $23 (rebajada de $47).",
        "price":       21.00,
        "image_url":   "https://images.unsplash.com/photo-1521369909029-2afed882baaa?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "accesorios",
        "name":        "Gorra Oficial Formula 1 — New Era 9FORTY",
        "description": "Gorra oficial de Fórmula 1 con el logo F1 bordado. Modelo New Era 9FORTY con visera curva y ajuste trasero metálico. Disponible en negro con detalle rojo. Producto oficial F1 Store, precio $35.",
        "price":       32.00,
        "image_url":   "https://images.unsplash.com/photo-1588850561407-ed78c282e89b?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "accesorios",
        "name":        "Llavero Neumático Pirelli 18\" — Oficial",
        "description": "Llavero oficial con réplica en miniatura del neumático Pirelli de 18 pulgadas utilizado en la F1 actual. Fabricado en goma y metal con el logo Pirelli P Zero. Perfecto como regalo para aficionados. Precio oficial Fueler Store: $35.",
        "price":       32.00,
        "image_url":   "https://images.unsplash.com/photo-1602143407151-7111542de6e8?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "accesorios",
        "name":        "Gorra Alpine F1 Team 2025 — New Era 9FORTY",
        "description": "Gorra oficial del equipo Alpine F1 2025 en azul marino con el logo Alpine bordado. Modelo New Era 9FORTY de visera curva y ajuste metálico trasero. Precio oficial Fueler Store: $45.",
        "price":       41.00,
        "image_url":   "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=600&h=600&fit=crop&q=85",
    },

    # ════════════════════════════════
    #  COLECCIONABLES
    # ════════════════════════════════
    {
        "category":    "coleccionable",
        "name":        "Póster Verstappen — The Orange Army, Zandvoort 2024",
        "description": "Póster oficial de coleccionista de Max Verstappen 'The Orange Army' del Gran Premio de los Países Bajos 2024 en Zandvoort. Edición grande, edición coleccionista Red Bull Racing. Impresión de alta calidad. Precio oficial Fueler Store: $150.",
        "price":       138.00,
        "image_url":   "https://images.unsplash.com/photo-1579952363873-27f3bade9f55?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "coleccionable",
        "name":        "Pop! Figure Verstappen #1 con Gorra — Red Bull",
        "description": "Figura coleccionable Funko Pop! oficial de Max Verstappen con su gorra Red Bull Racing. Número 1 de la colección. Caja con ventana para exposición. Producto oficial Red Bull Racing. Precio oficial Fueler Store: $30.",
        "price":       27.50,
        "image_url":   "https://images.unsplash.com/photo-1518604666860-9ed391f76460?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "coleccionable",
        "name":        "Taza Térmica Scuderia Ferrari — Official Shield",
        "description": "Taza térmica oficial Scuderia Ferrari con el escudo del cavallino rampante en relieve. Acero inoxidable de doble pared, mantiene la temperatura. Capacidad 350ml. Apta para lavavajillas. Precio oficial Fueler Store: $35.",
        "price":       32.00,
        "image_url":   "https://images.unsplash.com/photo-1541348263662-e068662d82af?w=600&h=600&fit=crop&q=85",
    },
    {
        "category":    "coleccionable",
        "name":        "Gorra McLaren Constructors Champions 2024",
        "description": "Gorra oficial conmemorativa del Campeonato de Constructores de McLaren 2024. Diseño exclusivo en papaya con el trofeo bordado y la inscripción 'Constructors Champions 2024'. Edición limitada. Precio oficial Fueler Store: $70.",
        "price":       64.00,
        "image_url":   "https://images.unsplash.com/photo-1503376780353-7e6692767b70?w=600&h=600&fit=crop&q=85",
    },
]


# ──────────────────────────────────────────────────────────────
def run_seed(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    count = conn.execute("SELECT COUNT(*) as c FROM products").fetchone()["c"]
    if count > 0:
        logger.info("[seed] BD ya tiene %d productos. Omitiendo seed.", count)
        conn.close()
        return

    logger.info("[seed] BD vacía. Insertando productos reales de F1...")

    # Crear usuario oficial
    user = conn.execute(
        "SELECT id FROM users WHERE email = ?", (STORE_USER["email"],)
    ).fetchone()

    if not user:
        pw_hash = bcrypt.hashpw(
            STORE_USER["password"].encode("utf-8"),
            bcrypt.gensalt(rounds=14),
        ).decode("utf-8")
        cursor = conn.execute(
            "INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)",
            (STORE_USER["username"], STORE_USER["email"], pw_hash, STORE_USER["balance"]),
        )
        user_id = cursor.lastrowid
        logger.info("[seed] Usuario oficial creado: %s", STORE_USER["email"])
    else:
        user_id = user["id"]

    stmt = (
        "INSERT INTO products (seller_id, name, description, category, price, image_url)"
        " VALUES (?, ?, ?, ?, ?, ?)"
    )
    for p in PRODUCTS:
        conn.execute(stmt, (
            user_id, p["name"], p["description"],
            p["category"], p["price"], p["image_url"],
        ))

    conn.commit()
    conn.close()

    from collections import Counter
    cats = Counter(p["category"] for p in PRODUCTS)
    logger.info("[seed] %d productos insertados:", len(PRODUCTS))
    for cat, n in sorted(cats.items()):
        logger.info("[seed]   %-14s -> %d", cat, n)