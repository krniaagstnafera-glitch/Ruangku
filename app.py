import os
import psycopg
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ruangku_secret_key")

DATABASE_URL = os.environ.get("DATABASE_URL")
_db_initialized = False


# ==================================================
# KONEKSI POSTGRESQL NEON
# Kompatibel dengan sebagian besar query SQLite lama
# ==================================================
class HybridRow(dict):
    def __init__(self, columns, values):
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def hybrid_row_factory(cursor):
    columns = [column.name for column in cursor.description]
    return lambda values: HybridRow(columns, values)


class DBConnection:
    def __init__(self):
        database_url = os.environ.get("DATABASE_URL")

        if not database_url:
            raise RuntimeError(
                "DATABASE_URL belum diatur di Vercel Environment Variables."
            )

        self.conn = psycopg.connect(
            database_url,
            row_factory=hybrid_row_factory,
            connect_timeout=10
        )

    def execute(self, sql, params=()):
        # Pengganti PRAGMA table_info khusus PostgreSQL
        if sql.strip().upper().startswith("PRAGMA TABLE_INFO"):
            return self.conn.execute(
                """
                SELECT column_name AS name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = %s
                ORDER BY ordinal_position
                """,
                ("reservasi",)
            )

        sql = sql.replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "SERIAL PRIMARY KEY"
        )
        sql = sql.replace("?", "%s")

        return self.conn.execute(sql, params)

    def executemany(self, sql, params):
        sql = sql.replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "SERIAL PRIMARY KEY"
        )
        sql = sql.replace("?", "%s")

        cursor = self.conn.cursor()
        cursor.executemany(sql, params)
        return cursor

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_db():
    return DBConnection()


# ==================================================
# MEMBUAT DATABASE DAN TABEL
# ==================================================
def init_db():
    conn = get_db()

    try:
        # TABEL RUANGAN
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ruangan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nama TEXT NOT NULL,
                kapasitas INTEGER NOT NULL
            )
        """)

        # TABEL RESERVASI
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reservasi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nama TEXT NOT NULL,
                nim TEXT NOT NULL,
                ruangan TEXT NOT NULL,
                tanggal TEXT NOT NULL,
                jam_mulai TEXT NOT NULL,
                jam_selesai TEXT NOT NULL,
                jumlah_peserta INTEGER NOT NULL,
                keperluan TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Menunggu',
                username TEXT
            )
        """)

        # Pastikan kolom username tersedia
        kolom = conn.execute(
            "PRAGMA table_info(reservasi)"
        ).fetchall()

        nama_kolom = [c["name"] for c in kolom]

        if "username" not in nama_kolom:
            conn.execute(
                "ALTER TABLE reservasi ADD COLUMN username TEXT"
            )

        # TABEL AKUN
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)

        # DATA RUANGAN AWAL
        jumlah = conn.execute(
            "SELECT COUNT(*) FROM ruangan"
        ).fetchone()[0]

        if jumlah == 0:
            data_ruangan = [
                ("FBTS1", 20),
                ("FBTS2", 20),
                ("FBTS3", 20),
                ("FBTS4", 20),
                ("FBTS5", 25),
                ("FBTS6", 25),
                ("FBTS7", 25),
                ("FBTS8", 25),
                ("LAB", 15)
            ]

            conn.executemany("""
                INSERT INTO ruangan (nama, kapasitas)
                VALUES (?, ?)
            """, data_ruangan)

        # AKUN ADMIN DEFAULT
        admin = conn.execute("""
            SELECT id, password FROM users
            WHERE username = 'admin'
        """).fetchone()

        if admin is None:
            conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (
                "admin",
                generate_password_hash("admin123"),
                "admin"
            ))
        else:
            password_admin = admin["password"]

            if not password_admin.startswith(("scrypt:", "pbkdf2:")):
                conn.execute("""
                    UPDATE users
                    SET password = ?
                    WHERE id = ?
                """, (
                    generate_password_hash(password_admin),
                    admin["id"]
                ))

        # Hapus akun bersama lama jika masih ada
        conn.execute("""
            DELETE FROM users
            WHERE username = 'user'
            AND role = 'user'
        """)

        # MIGRASI PASSWORD LAMA
        users = conn.execute("""
            SELECT id, password FROM users
            WHERE role = 'user'
        """).fetchall()

        for akun in users:
            password_lama = akun["password"]

            if not password_lama.startswith(("scrypt:", "pbkdf2:")):
                conn.execute("""
                    UPDATE users
                    SET password = ?
                    WHERE id = ?
                """, (
                    generate_password_hash(password_lama),
                    akun["id"]
                ))

        conn.commit()

    except Exception:
        conn.conn.rollback()
        raise

    finally:
        conn.close()


# ==================================================
# INISIALISASI DATABASE SAAT ADA REQUEST
# ==================================================
@app.before_request
def ensure_database():
    global _db_initialized

    if not _db_initialized:
        init_db()
        _db_initialized = True


# ==================================================
# HALAMAN PILIHAN LOGIN
# ==================================================
@app.route("/login")
def login():
    return render_template("login.html")


# ==================================================
# LOGIN MAHASISWA
# ==================================================
@app.route("/login/mahasiswa", methods=["GET", "POST"])
def login_mahasiswa():
    return proses_login("user", "Login Mahasiswa")


# ==================================================
# LOGIN ADMIN
# ==================================================
@app.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    return proses_login("admin", "Login Admin")


# ==================================================
# PROSES LOGIN
# ==================================================
def proses_login(role_tujuan, judul):
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        finally:
            conn.close()

        if (
            user
            and user["role"] == role_tujuan
            and check_password_hash(user["password"], password)
        ):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]

            if role_tujuan == "admin":
                return redirect(url_for("admin"))

            return redirect(url_for("dashboard_user"))

        return render_template(
            "login_form.html",
            judul=judul,
            error="NIM/username atau password salah."
        )

    return render_template("login_form.html", judul=judul)


# ==================================================
# DAFTAR AKUN MAHASISWA
# ==================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nim = request.form.get("nim", "").strip()
        password = request.form.get("password", "")
        konfirmasi = request.form.get("konfirmasi", "")

        if not nim or not password or not konfirmasi:
            return render_template(
                "register.html",
                error="Semua data harus diisi."
            )

        if not nim.isdigit():
            return render_template(
                "register.html",
                error="NIM harus berupa angka."
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password minimal 8 karakter."
            )

        if password != konfirmasi:
            return render_template(
                "register.html",
                error="Konfirmasi password tidak cocok."
            )

        conn = get_db()

        try:
            akun = conn.execute("""
                SELECT id FROM users WHERE username = ?
            """, (nim,)).fetchone()

            if akun:
                return render_template(
                    "register.html",
                    error="NIM sudah terdaftar. Silakan login."
                )

            conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, 'user')
            """, (
                nim,
                generate_password_hash(password)
            ))

            conn.commit()

        except Exception:
            conn.conn.rollback()
            raise

        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# ==================================================
# LOGOUT
# ==================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==================================================
# DASHBOARD MAHASISWA
# ==================================================
@app.route("/dashboard-user")
def dashboard_user():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        ruangan = conn.execute(
            "SELECT * FROM ruangan"
        ).fetchall()
    finally:
        conn.close()

    return render_template("dashboard_user.html", ruangan=ruangan)


# ==================================================
# HALAMAN UTAMA
# ==================================================
@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin"))

    return redirect(url_for("dashboard_user"))


# ==================================================
# FORM RESERVASI
# ==================================================
@app.route("/reservasi", methods=["GET", "POST"])
def reservasi():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        ruangan = conn.execute(
            "SELECT * FROM ruangan"
        ).fetchall()

        if request.method == "POST":
            nama = request.form["nama"]
            nim = request.form["nim"]
            nama_ruangan = request.form["ruangan"]
            tanggal = request.form["tanggal"]
            jam_mulai = request.form["jam_mulai"]
            jam_selesai = request.form["jam_selesai"]
            jumlah_peserta = int(request.form["jumlah_peserta"])
            keperluan = request.form["keperluan"]

            if jam_selesai <= jam_mulai:
                return render_template(
                    "reservasi.html",
                    ruangan=ruangan,
                    error="Jam selesai harus lebih besar dari jam mulai."
                )

            sekarang = datetime.now()
            waktu_reservasi = datetime.strptime(
                f"{tanggal} {jam_mulai}",
                "%Y-%m-%d %H:%M"
            )

            if waktu_reservasi < sekarang:
                return render_template(
                    "reservasi.html",
                    ruangan=ruangan,
                    error=(
                        "Inputan Anda melewati jam sekarang. "
                        "Silakan pilih tanggal atau waktu yang akan datang."
                    )
                )

            data_ruangan = conn.execute("""
                SELECT * FROM ruangan WHERE nama = ?
            """, (nama_ruangan,)).fetchone()

            if data_ruangan is None:
                return render_template(
                    "reservasi.html",
                    ruangan=ruangan,
                    error="Ruangan tidak ditemukan."
                )

            kapasitas = data_ruangan["kapasitas"]

            if jumlah_peserta > kapasitas:
                return render_template(
                    "reservasi.html",
                    ruangan=ruangan,
                    error=(
                        f"Reservasi ditolak. {nama_ruangan} "
                        f"hanya memiliki kapasitas {kapasitas} orang."
                    )
                )

            bentrok = conn.execute("""
                SELECT * FROM reservasi
                WHERE ruangan = ?
                  AND tanggal = ?
                  AND status != 'Ditolak'
                  AND jam_mulai < ?
                  AND jam_selesai > ?
            """, (
                nama_ruangan, tanggal, jam_selesai, jam_mulai
            )).fetchone()

            if bentrok:
                return render_template(
                    "reservasi.html",
                    ruangan=ruangan,
                    error=(
                        f"Reservasi ditolak. {nama_ruangan} "
                        "sudah digunakan pada waktu tersebut."
                    )
                )

            conn.execute("""
                INSERT INTO reservasi (
                    nama, nim, ruangan, tanggal, jam_mulai,
                    jam_selesai, jumlah_peserta, keperluan,
                    status, username
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Menunggu', ?)
            """, (
                nama, nim, nama_ruangan, tanggal, jam_mulai,
                jam_selesai, jumlah_peserta, keperluan,
                session["username"]
            ))

            conn.commit()
            return redirect(url_for("reservasi_saya"))

        ruangan_pilihan = request.args.get("ruangan", "")

        return render_template(
            "reservasi.html",
            ruangan=ruangan,
            ruangan_pilihan=ruangan_pilihan
        )

    finally:
        conn.close()


# ==================================================
# RESERVASI SAYA
# ==================================================
@app.route("/reservasi-saya")
def reservasi_saya():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        data = conn.execute("""
            SELECT * FROM reservasi
            WHERE username = ?
            ORDER BY tanggal, jam_mulai
        """, (session["username"],)).fetchall()
    finally:
        conn.close()

    return render_template("reservasi_saya.html", reservasi=data)


# ==================================================
# HAPUS RESERVASI MAHASISWA
# ==================================================
@app.route("/reservasi/hapus/<int:id>", methods=["POST"])
def hapus_reservasi(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        conn.execute("""
            DELETE FROM reservasi
            WHERE id = ? AND username = ?
        """, (id, session["username"]))

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("reservasi_saya"))


# ==================================================
# CEK KETERSEDIAAN
# ==================================================
@app.route("/ketersediaan", methods=["GET", "POST"])
def ketersediaan():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        semua_ruangan = conn.execute(
            "SELECT * FROM ruangan"
        ).fetchall()

        hasil = []
        tanggal = ""
        jam_mulai = ""
        jam_selesai = ""

        if request.method == "POST":
            tanggal = request.form["tanggal"]
            jam_mulai = request.form["jam_mulai"]
            jam_selesai = request.form["jam_selesai"]

            if jam_selesai > jam_mulai:
                for r in semua_ruangan:
                    bentrok = conn.execute("""
                        SELECT * FROM reservasi
                        WHERE ruangan = ?
                          AND tanggal = ?
                          AND status != 'Ditolak'
                          AND jam_mulai < ?
                          AND jam_selesai > ?
                    """, (
                        r["nama"], tanggal, jam_selesai, jam_mulai
                    )).fetchone()

                    hasil.append({
                        "nama": r["nama"],
                        "kapasitas": r["kapasitas"],
                        "status": "Terisi" if bentrok else "Tersedia"
                    })

        return render_template(
            "ketersediaan.html",
            hasil=hasil,
            tanggal=tanggal,
            jam_mulai=jam_mulai,
            jam_selesai=jam_selesai
        )
    finally:
        conn.close()


# ==================================================
# DASHBOARD ADMIN
# ==================================================
@app.route("/admin")
def admin():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    try:
        data = conn.execute("""
            SELECT * FROM reservasi
            ORDER BY tanggal, jam_mulai
        """).fetchall()

        ruangan = conn.execute("""
            SELECT * FROM ruangan ORDER BY id
        """).fetchall()
    finally:
        conn.close()

    sekarang = datetime.now()

    return render_template(
        "admin.html",
        reservasi=data,
        ruangan=ruangan,
        current_date=sekarang.strftime("%Y-%m-%d"),
        current_time=sekarang.strftime("%H:%M")
    )


# ==================================================
# TAMBAH RUANGAN
# ==================================================
@app.route("/admin/ruangan/tambah", methods=["POST"])
def tambah_ruangan():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    nama = request.form.get("nama", "").strip()
    kapasitas = request.form.get("kapasitas", "").strip()

    if not nama:
        return redirect(url_for("admin"))

    try:
        kapasitas = int(kapasitas)
    except ValueError:
        return redirect(url_for("admin"))

    if kapasitas <= 0:
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        ruangan_sama = conn.execute("""
            SELECT * FROM ruangan WHERE nama = ?
        """, (nama,)).fetchone()

        if ruangan_sama:
            return redirect(url_for("admin"))

        conn.execute("""
            INSERT INTO ruangan (nama, kapasitas)
            VALUES (?, ?)
        """, (nama, kapasitas))

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# EDIT RUANGAN
# ==================================================
@app.route("/admin/ruangan/edit/<int:id>", methods=["POST"])
def edit_ruangan(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    nama = request.form.get("nama", "").strip()
    kapasitas = request.form.get("kapasitas", "").strip()

    if not nama or not kapasitas:
        return redirect(url_for("admin"))

    try:
        kapasitas = int(kapasitas)
    except ValueError:
        return redirect(url_for("admin"))

    if kapasitas <= 0:
        return redirect(url_for("admin"))

    conn = get_db()

    try:
        conn.execute("""
            UPDATE ruangan
            SET nama = ?, kapasitas = ?
            WHERE id = ?
        """, (nama, kapasitas, id))

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# HAPUS RUANGAN
# ==================================================
@app.route("/admin/ruangan/hapus/<int:id>", methods=["POST"])
def hapus_ruangan(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    try:
        ruangan = conn.execute("""
            SELECT * FROM ruangan WHERE id = ?
        """, (id,)).fetchone()

        if ruangan is not None:
            conn.execute("""
                DELETE FROM ruangan WHERE id = ?
            """, (id,))
            conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# SETUJUI RESERVASI
# ==================================================
@app.route("/admin/setujui/<int:id>", methods=["POST"])
def setujui(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    try:
        conn.execute("""
            UPDATE reservasi
            SET status = 'Disetujui'
            WHERE id = ?
        """, (id,))

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# TOLAK RESERVASI
# ==================================================
@app.route("/admin/tolak/<int:id>", methods=["POST"])
def tolak(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    try:
        conn.execute("""
            UPDATE reservasi
            SET status = 'Ditolak'
            WHERE id = ?
        """, (id,))

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# HAPUS RESERVASI LAMPAU
# ==================================================
@app.route("/admin/reservasi/hapus/<int:id>", methods=["POST"])
def hapus_reservasi_lampau(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    try:
        reservasi = conn.execute("""
            SELECT * FROM reservasi WHERE id = ?
        """, (id,)).fetchone()

        if reservasi is not None:
            sekarang = datetime.now()

            waktu_reservasi = datetime.strptime(
                f"{reservasi['tanggal']} {reservasi['jam_selesai']}",
                "%Y-%m-%d %H:%M"
            )

            if waktu_reservasi < sekarang:
                conn.execute("""
                    DELETE FROM reservasi WHERE id = ?
                """, (id,))

                conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin"))


# ==================================================
# API LOGIN ANDROID
# ==================================================
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT * FROM users WHERE username = ?
        """, (username,)).fetchone()
    finally:
        conn.close()

    if user and check_password_hash(user["password"], password):
        return {
            "success": True,
            "username": user["username"],
            "role": user["role"]
        }

    return {
        "success": False,
        "message": "Username atau password salah."
    }, 401


# ==================================================
# API RESERVASI ANDROID
# ==================================================
@app.route("/api/reservasi", methods=["POST"])
def api_reservasi():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    nama = data.get("nama", "")
    nim = data.get("nim", "")
    nama_ruangan = data.get("ruangan", "")
    tanggal = data.get("tanggal", "")
    jam_mulai = data.get("jam_mulai", "")
    jam_selesai = data.get("jam_selesai", "")
    keperluan = data.get("keperluan", "")

    try:
        jumlah_peserta = int(data.get("jumlah_peserta", 0))
    except (TypeError, ValueError):
        jumlah_peserta = 0

    if not all([
        username, nama, nim, nama_ruangan, tanggal,
        jam_mulai, jam_selesai, jumlah_peserta, keperluan
    ]):
        return {
            "success": False,
            "message": "Semua data harus diisi."
        }, 400

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT * FROM users
            WHERE username = ? AND role = 'user'
        """, (username,)).fetchone()

        if user is None:
            return {
                "success": False,
                "message": "User tidak ditemukan."
            }, 401

        if jam_selesai <= jam_mulai:
            return {
                "success": False,
                "message": "Jam selesai harus lebih besar dari jam mulai."
            }, 400

        try:
            waktu_reservasi = datetime.strptime(
                f"{tanggal} {jam_mulai}",
                "%Y-%m-%d %H:%M"
            )
        except ValueError:
            return {
                "success": False,
                "message": "Format tanggal atau jam tidak valid."
            }, 400

        if waktu_reservasi < datetime.now():
            return {
                "success": False,
                "message": "Tanggal atau waktu reservasi sudah lewat."
            }, 400

        data_ruangan = conn.execute("""
            SELECT * FROM ruangan WHERE nama = ?
        """, (nama_ruangan,)).fetchone()

        if data_ruangan is None:
            return {
                "success": False,
                "message": "Ruangan tidak ditemukan."
            }, 400

        if jumlah_peserta > data_ruangan["kapasitas"]:
            return {
                "success": False,
                "message": (
                    f"Reservasi ditolak. {nama_ruangan} "
                    f"hanya memiliki kapasitas {data_ruangan['kapasitas']} orang."
                )
            }, 400

        bentrok = conn.execute("""
            SELECT * FROM reservasi
            WHERE ruangan = ?
              AND tanggal = ?
              AND status != 'Ditolak'
              AND jam_mulai < ?
              AND jam_selesai > ?
        """, (
            nama_ruangan, tanggal, jam_selesai, jam_mulai
        )).fetchone()

        if bentrok:
            return {
                "success": False,
                "message": (
                    f"Reservasi ditolak. {nama_ruangan} "
                    "sudah digunakan pada waktu tersebut."
                )
            }, 400

        conn.execute("""
            INSERT INTO reservasi (
                nama, nim, ruangan, tanggal, jam_mulai,
                jam_selesai, jumlah_peserta, keperluan,
                status, username
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Menunggu', ?)
        """, (
            nama, nim, nama_ruangan, tanggal, jam_mulai,
            jam_selesai, jumlah_peserta, keperluan, username
        ))

        conn.commit()

        return {
            "success": True,
            "message": "Reservasi berhasil diajukan."
        }

    except Exception:
        conn.conn.rollback()
        raise

    finally:
        conn.close()


# ==================================================
# JALANKAN LOKAL
# ==================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
