from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "ruangku_secret_key"

DATABASE = "ruangku.db"


# ==================================================
# KONEKSI DATABASE
# ==================================================
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ==================================================
# MEMBUAT DATABASE
# ==================================================
def init_db():
    conn = get_db()

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

    # TAMBAHKAN KOLOM USERNAME JIKA BELUM ADA
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

        if not password_admin.startswith(
            ("scrypt:", "pbkdf2:")
        ):
            conn.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (
                generate_password_hash(password_admin),
                admin["id"]
            ))

    # HAPUS AKUN MAHASISWA BERSAMA YANG LAMA
    # Akun mahasiswa pribadi tidak dihapus.
    conn.execute("""
        DELETE FROM users
        WHERE username = 'user'
        AND role = 'user'
    """)

    # MIGRASI PASSWORD LAMA KE PASSWORD TER-HASH
    users = conn.execute("""
        SELECT id, password FROM users
        WHERE role = 'user'
    """).fetchall()

    for akun in users:
        password_lama = akun["password"]

        if not password_lama.startswith(
            ("scrypt:", "pbkdf2:")
        ):
            conn.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (
                generate_password_hash(password_lama),
                akun["id"]
            ))

    conn.commit()
    conn.close()
    
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
# PROSES LOGIN BERSAMA
# ==================================================
def proses_login(role_tujuan, judul):
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
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

    return render_template(
        "login_form.html",
        judul=judul
    )

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

        akun = conn.execute("""
            SELECT id FROM users
            WHERE username = ?
        """, (nim,)).fetchone()

        if akun:
            conn.close()
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
# DASHBOARD USER
# ==================================================
@app.route("/dashboard-user")
def dashboard_user():

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    ruangan = conn.execute(
        "SELECT * FROM ruangan"
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard_user.html",
        ruangan=ruangan
    )


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

        # ==================================================
        # CEK JAM SELESAI
        # ==================================================
        if jam_selesai <= jam_mulai:

            conn.close()

            return render_template(
                "reservasi.html",
                ruangan=ruangan,
                error="Jam selesai harus lebih besar dari jam mulai."
            )

        # ==================================================
        # CEK TANGGAL DAN JAM TIDAK BOLEH MASA LALU
        # ==================================================
        sekarang = datetime.now()

        waktu_reservasi = datetime.strptime(
            f"{tanggal} {jam_mulai}",
            "%Y-%m-%d %H:%M"
        )

        if waktu_reservasi < sekarang:

            conn.close()

            return render_template(
                "reservasi.html",
                ruangan=ruangan,
                error=(
                    "Inputan Anda melewati jam sekarang. "
                    "Silakan pilih tanggal atau waktu yang akan datang."
                )
            )

        # ==================================================
        # CEK RUANGAN
        # ==================================================
        data_ruangan = conn.execute(
            """
            SELECT * FROM ruangan
            WHERE nama = ?
            """,
            (nama_ruangan,)
        ).fetchone()

        if data_ruangan is None:

            conn.close()

            return render_template(
                "reservasi.html",
                ruangan=ruangan,
                error="Ruangan tidak ditemukan."
            )

        kapasitas = data_ruangan["kapasitas"]

        # ==================================================
        # CEK KAPASITAS
        # ==================================================
        if jumlah_peserta > kapasitas:

            conn.close()

            return render_template(
                "reservasi.html",
                ruangan=ruangan,
                error=(
                    f"Reservasi ditolak. {nama_ruangan} "
                    f"hanya memiliki kapasitas {kapasitas} orang."
                )
            )

        # ==================================================
        # CEK BENTROK
        # ==================================================
        bentrok = conn.execute(
            """
            SELECT * FROM reservasi
            WHERE ruangan = ?
            AND tanggal = ?
            AND status != 'Ditolak'
            AND jam_mulai < ?
            AND jam_selesai > ?
            """,
            (
                nama_ruangan,
                tanggal,
                jam_selesai,
                jam_mulai
            )
        ).fetchone()

        if bentrok:

            conn.close()

            return render_template(
                "reservasi.html",
                ruangan=ruangan,
                error=(
                    f"Reservasi ditolak. {nama_ruangan} "
                    "sudah digunakan pada waktu tersebut."
                )
            )

        # ==================================================
        # SIMPAN RESERVASI
        # ==================================================
        conn.execute(
            """
            INSERT INTO reservasi (
                nama,
                nim,
                ruangan,
                tanggal,
                jam_mulai,
                jam_selesai,
                jumlah_peserta,
                keperluan,
                status,
                username
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Menunggu', ?)
            """,
            (
                nama,
                nim,
                nama_ruangan,
                tanggal,
                jam_mulai,
                jam_selesai,
                jumlah_peserta,
                keperluan,
                session["username"]
            )
        )

        conn.commit()
        conn.close()

        return redirect(url_for("reservasi_saya"))

    # ==================================================
    # PILIHAN RUANGAN
    # ==================================================
    ruangan_pilihan = request.args.get(
        "ruangan",
        ""
    )

    conn.close()

    return render_template(
        "reservasi.html",
        ruangan=ruangan,
        ruangan_pilihan=ruangan_pilihan
    )


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

    # Hanya menampilkan reservasi milik user yang login
    data = conn.execute(
        """
        SELECT * FROM reservasi
        WHERE username = ?
        ORDER BY tanggal, jam_mulai
        """,
        (session["username"],)
    ).fetchall()

    conn.close()

    return render_template(
        "reservasi_saya.html",
        reservasi=data
    )


# ==================================================
# HAPUS RESERVASI
# ==================================================
@app.route("/reservasi/hapus/<int:id>", methods=["POST"])
def hapus_reservasi(id):

    # Pastikan user sudah login
    if "username" not in session:
        return redirect(url_for("login"))

    # Hanya user yang boleh menghapus reservasi
    if session.get("role") != "user":
        return redirect(url_for("admin"))

    conn = get_db()

    # ==================================================
    # HAPUS RESERVASI MILIK USER
    # ==================================================
    # User hanya bisa menghapus reservasi miliknya sendiri.
    # Status Menunggu, Disetujui, dan Ditolak semuanya
    # dapat dihapus.
    conn.execute(
        """
        DELETE FROM reservasi
        WHERE id = ?
        AND username = ?
        """,
        (id, session["username"])
    )

    conn.commit()
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

                bentrok = conn.execute(
                    """
                    SELECT * FROM reservasi
                    WHERE ruangan = ?
                    AND tanggal = ?
                    AND status != 'Ditolak'
                    AND jam_mulai < ?
                    AND jam_selesai > ?
                    """,
                    (
                        r["nama"],
                        tanggal,
                        jam_selesai,
                        jam_mulai
                    )
                ).fetchone()

                if bentrok:
                    status = "Terisi"
                else:
                    status = "Tersedia"

                hasil.append({
                    "nama": r["nama"],
                    "kapasitas": r["kapasitas"],
                    "status": status
                })

    conn.close()

    return render_template(
        "ketersediaan.html",
        hasil=hasil,
        tanggal=tanggal,
        jam_mulai=jam_mulai,
        jam_selesai=jam_selesai
    )

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

    # Data reservasi
    data = conn.execute(
        """
        SELECT * FROM reservasi
        ORDER BY tanggal, jam_mulai
        """
    ).fetchall()

    # Data ruangan
    ruangan = conn.execute(
        """
        SELECT * FROM ruangan
        ORDER BY id
        """
    ).fetchall()

    conn.close()

    # Waktu sekarang
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

    # Pastikan sudah login
    if "username" not in session:
        return redirect(url_for("login"))

    # Hanya admin yang boleh menambah ruangan
    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    nama = request.form["nama"].strip()
    kapasitas = request.form["kapasitas"].strip()

    # Cek nama ruangan
    if not nama:
        return redirect(url_for("admin"))

    # Cek kapasitas
    try:
        kapasitas = int(kapasitas)
    except ValueError:
        return redirect(url_for("admin"))

    if kapasitas <= 0:
        return redirect(url_for("admin"))

    conn = get_db()

    # Cek apakah nama ruangan sudah digunakan
    ruangan_sama = conn.execute(
        """
        SELECT * FROM ruangan
        WHERE nama = ?
        """,
        (nama,)
    ).fetchone()

    if ruangan_sama:
        conn.close()

        return redirect(url_for("admin"))

    # Simpan ruangan baru
    conn.execute(
        """
        INSERT INTO ruangan (nama, kapasitas)
        VALUES (?, ?)
        """,
        (nama, kapasitas)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

# ==================================================
# EDIT / RENAME RUANGAN
# ==================================================
@app.route("/admin/ruangan/edit/<int:id>", methods=["POST"])
def edit_ruangan(id):

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    nama = request.form.get("nama", "").strip()
    kapasitas = request.form.get("kapasitas", "").strip()

    print("EDIT ID:", id)
    print("NAMA:", nama)
    print("KAPASITAS:", kapasitas)

    if not nama or not kapasitas:
        return redirect(url_for("admin"))

    try:
        kapasitas = int(kapasitas)
    except ValueError:
        return redirect(url_for("admin"))

    if kapasitas <= 0:
        return redirect(url_for("admin"))

    conn = get_db()

    conn.execute(
        """
        UPDATE ruangan
        SET nama = ?, kapasitas = ?
        WHERE id = ?
        """,
        (nama, kapasitas, id)
    )

    conn.commit()

    print("DATA BERHASIL DIUPDATE")

    conn.close()

    return redirect(url_for("admin"))

@app.route("/admin/ruangan/hapus/<int:id>", methods=["POST"])
def hapus_ruangan(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    ruangan = conn.execute(
        """
        SELECT * FROM ruangan
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if ruangan is None:
        conn.close()
        return redirect(url_for("admin"))

    conn.execute(
        """
        DELETE FROM ruangan
        WHERE id = ?
        """,
        (id,)
    )

    conn.commit()
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

    conn.execute(
        """
        UPDATE reservasi
        SET status = 'Disetujui'
        WHERE id = ?
        """,
        (id,)
    )

    conn.commit()
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

    conn.execute(
        """
        UPDATE reservasi
        SET status = 'Ditolak'
        WHERE id = ?
        """,
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

@app.route("/admin/reservasi/hapus/<int:id>", methods=["POST"])
def hapus_reservasi_lampau(id):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("dashboard_user"))

    conn = get_db()

    reservasi = conn.execute(
        """
        SELECT * FROM reservasi
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if reservasi is None:
        conn.close()
        return redirect(url_for("admin"))

    # Ambil tanggal dan jam sekarang
    sekarang = datetime.now()
    waktu_reservasi = datetime.strptime(
        f"{reservasi['tanggal']} {reservasi['jam_selesai']}",
        "%Y-%m-%d %H:%M"
    )

    # Hanya boleh menghapus jika reservasi sudah lewat
    if waktu_reservasi < sekarang:
        conn.execute(
            """
            DELETE FROM reservasi
            WHERE id = ?
            """,
            (id,)
        )

        conn.commit()

    conn.close()

    return redirect(url_for("admin"))


# ==================================================
# API LOGIN UNTUK APLIKASI ANDROID
# ==================================================
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute("""
        SELECT * FROM users
        WHERE username = ?
    """, (username,)).fetchone()
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
# API RESERVASI UNTUK APLIKASI ANDROID
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
        username,
        nama,
        nim,
        nama_ruangan,
        tanggal,
        jam_mulai,
        jam_selesai,
        jumlah_peserta,
        keperluan
    ]):
        return {
            "success": False,
            "message": "Semua data harus diisi."
        }, 400

    conn = get_db()

    # Cek user
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND role = 'user'",
        (username,)
    ).fetchone()

    if user is None:
        conn.close()
        return {
            "success": False,
            "message": "User tidak ditemukan."
        }, 401

    # Cek jam selesai
    if jam_selesai <= jam_mulai:
        conn.close()
        return {
            "success": False,
            "message": "Jam selesai harus lebih besar dari jam mulai."
        }, 400

    # Cek tanggal dan jam tidak boleh masa lalu
    sekarang = datetime.now()

    try:
        waktu_reservasi = datetime.strptime(
            f"{tanggal} {jam_mulai}",
            "%Y-%m-%d %H:%M"
        )
    except ValueError:
        conn.close()
        return {
            "success": False,
            "message": "Format tanggal atau jam tidak valid."
        }, 400

    if waktu_reservasi < sekarang:
        conn.close()
        return {
            "success": False,
            "message": "Tanggal atau waktu reservasi sudah lewat."
        }, 400

    # Cek ruangan
    data_ruangan = conn.execute(
        """
        SELECT * FROM ruangan
        WHERE nama = ?
        """,
        (nama_ruangan,)
    ).fetchone()

    if data_ruangan is None:
        conn.close()
        return {
            "success": False,
            "message": "Ruangan tidak ditemukan."
        }, 400

    kapasitas = data_ruangan["kapasitas"]

    # Cek kapasitas
    if jumlah_peserta > kapasitas:
        conn.close()
        return {
            "success": False,
            "message": (
                f"Reservasi ditolak. {nama_ruangan} "
                f"hanya memiliki kapasitas {kapasitas} orang."
            )
        }, 400

    # Cek bentrok
    bentrok = conn.execute(
        """
        SELECT * FROM reservasi
        WHERE ruangan = ?
        AND tanggal = ?
        AND status != 'Ditolak'
        AND jam_mulai < ?
        AND jam_selesai > ?
        """,
        (
            nama_ruangan,
            tanggal,
            jam_selesai,
            jam_mulai
        )
    ).fetchone()

    if bentrok:
        conn.close()
        return {
            "success": False,
            "message": (
                f"Reservasi ditolak. {nama_ruangan} "
                "sudah digunakan pada waktu tersebut."
            )
        }, 400

    # Simpan reservasi
    conn.execute(
        """
        INSERT INTO reservasi (
            nama,
            nim,
            ruangan,
            tanggal,
            jam_mulai,
            jam_selesai,
            jumlah_peserta,
            keperluan,
            status,
            username
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Menunggu', ?)
        """,
        (
            nama,
            nim,
            nama_ruangan,
            tanggal,
            jam_mulai,
            jam_selesai,
            jumlah_peserta,
            keperluan,
            username
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Reservasi berhasil diajukan."
    }


# ==================================================
# MENJALANKAN APLIKASI
# ==================================================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)