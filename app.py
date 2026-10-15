from flask import Flask, jsonify, request, session, send_from_directory, Response
import sqlite3
import csv
import io
import os
import time
from collections import defaultdict, deque
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# الأسرار محفوظة في ملف محلي منفصل لا يُشارك ولا يُرفع إلى الإنترنت.
try:
    from private_settings import SECRET_KEY, ADMIN_PASSWORD
except ImportError as exc:
    raise RuntimeError(
        "ملف private_settings.py غير موجود. انسخ private_settings.example.py إلى "
        "private_settings.py واضبط SECRET_KEY وADMIN_PASSWORD قبل تشغيل الموقع."
    ) from exc

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY يجب أن يكون مفتاحًا عشوائيًا بطول 32 حرفًا على الأقل.")
if not ADMIN_PASSWORD or ADMIN_PASSWORD == "CHANGE_THIS_TO_A_LONG_UNIQUE_PASSWORD":
    raise RuntimeError("غيّر ADMIN_PASSWORD داخل private_settings.py إلى كلمة مرور قوية قبل التشغيل.")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # اترك BARIQ_HTTPS=0 للتشغيل المحلي عبر http://127.0.0.1.
    # اضبط BARIQ_HTTPS=1 فقط بعد تشغيل الموقع خلف HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("BARIQ_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 4,
)

# تحديد محاولات تسجيل دخول المدرس: 5 محاولات خلال 10 دقائق لكل عنوان IP.
_admin_login_attempts = defaultdict(deque)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")

# ==========================================
# الاتصال بقاعدة البيانات
# ==========================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ==========================================
# إنشاء قاعدة البيانات
# ==========================================

def init_database():

    conn = get_db()
    cursor = conn.cursor()

    # جدول الصفوف
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    """)

    # جدول الامتحانات
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            class_id INTEGER NOT NULL,
            duration INTEGER NOT NULL DEFAULT 30,
            published INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (class_id) REFERENCES classes(id)
        )
    """)

    # جدول الأسئلة
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            correct_answer TEXT NOT NULL,
            FOREIGN KEY (exam_id) REFERENCES exams(id)
        )
    """)

    # جدول النتائج
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            student_code TEXT NOT NULL,
            class_id INTEGER NOT NULL,
            exam_id INTEGER NOT NULL,
            correct INTEGER NOT NULL,
            wrong INTEGER NOT NULL,
            total INTEGER NOT NULL,
            percentage REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (class_id) REFERENCES classes(id),
            FOREIGN KEY (exam_id) REFERENCES exams(id)
        )
    """)

    # تفاصيل إجابات الطلاب في كل نتيجة
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS result_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            student_answer TEXT NOT NULL DEFAULT '',
            correct_answer TEXT NOT NULL,
            is_correct INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (result_id) REFERENCES results(id),
            FOREIGN KEY (question_id) REFERENCES questions(id)
        )
    """)

    # حسابات الطلاب (إضافة جديدة لا تحذف أو تستبدل أي بيانات قديمة)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS student_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            class_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (class_id) REFERENCES classes(id)
        )
    """)

    # تحديث بنية جدول الأسئلة مع الحفاظ على الأسئلة القديمة
    question_columns = [row[1] for row in cursor.execute("PRAGMA table_info(questions)").fetchall()]

    if "question_type" not in question_columns:
        cursor.execute(
            "ALTER TABLE questions ADD COLUMN question_type TEXT NOT NULL DEFAULT 'multiple_choice'"
        )

    # ربط النتائج بحساب الطالب اختياريًا، مع الحفاظ على النتائج القديمة كما هي.
    # نقاط ومستوى الطالب القابلان للتعديل من لوحة الإدارة
    account_columns = [row[1] for row in cursor.execute("PRAGMA table_info(student_accounts)").fetchall()]
    if "points" not in account_columns:
        cursor.execute("ALTER TABLE student_accounts ADD COLUMN points INTEGER NOT NULL DEFAULT 0")
    if "level" not in account_columns:
        cursor.execute("ALTER TABLE student_accounts ADD COLUMN level INTEGER NOT NULL DEFAULT 1")

    result_columns = [row[1] for row in cursor.execute("PRAGMA table_info(results)").fetchall()]

    if "student_account_id" not in result_columns:
        cursor.execute(
            "ALTER TABLE results ADD COLUMN student_account_id INTEGER"
        )
    # الصفوف
    classes = [
        "الصف الرابع الابتدائي",
        "الصف الخامس الابتدائي",
        "الصف السادس الابتدائي",
        "الصف الأول الإعدادي",
        "الصف الثاني الإعدادي",
        "الصف الثالث الإعدادي"
    ]

    for class_name in classes:
        cursor.execute(
            "INSERT OR IGNORE INTO classes (name) VALUES (?)",
            (class_name,)
        )

    conn.commit()
    conn.close()

# ==========================================
# حماية لوحة التحكم
# ==========================================

def admin_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("admin_logged_in"):
            return jsonify({
                "error": "غير مصرح"
            }), 401

        return func(*args, **kwargs)

    return wrapper

# ==========================================
# صفحات الموقع
# ==========================================

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/images/<path:filename>")
def teacher_images(filename):
    return send_from_directory(os.path.join(BASE_DIR, "images"), filename)

@app.route("/index.html")
def index_page():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/exams.html")
def exams_page():
    return send_from_directory(BASE_DIR, "exams.html")

@app.route("/student.html")
def student_page():
    return send_from_directory(BASE_DIR, "student.html")

@app.route("/student-login")
@app.route("/student-login.html")
def student_login_page():
    return send_from_directory(BASE_DIR, "student-login.html")

@app.route("/student-dashboard")
@app.route("/student-dashboard.html")
def student_dashboard_page():
    return send_from_directory(BASE_DIR, "student-dashboard.html")

@app.route("/api/student/register", methods=["POST"])
def student_register():
    data = request.get_json(silent=True) or {}
    full_name = str(data.get("full_name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    class_id = data.get("class_id")

    if len(full_name) < 3:
        return jsonify({"error": "اكتب الاسم الكامل بشكل صحيح"}), 400
    if not username or len(username) < 4 or not username.replace("_", "").isalnum():
        return jsonify({"error": "اسم المستخدم يجب أن يكون 4 أحرف أو أرقام على الأقل، ويسمح بالشرطة السفلية"}), 400
    if len(password) < 8:
        return jsonify({"error": "كلمة المرور يجب ألا تقل عن 8 أحرف"}), 400
    try:
        class_id = int(class_id)
    except (TypeError, ValueError):
        return jsonify({"error": "اختر الصف الدراسي"}), 400

    conn = get_db()
    if not conn.execute("SELECT id FROM classes WHERE id = ?", (class_id,)).fetchone():
        conn.close()
        return jsonify({"error": "الصف الدراسي غير صحيح"}), 400
    try:
        cur = conn.execute("""INSERT INTO student_accounts
            (full_name, username, password_hash, class_id) VALUES (?, ?, ?, ?)""",
            (full_name, username, generate_password_hash(password), class_id))
        conn.commit()
        account_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "اسم المستخدم مستخدم بالفعل، جرّب اسمًا آخر"}), 409
    conn.close()
    session["student_account_id"] = account_id
    return jsonify({"success": True, "message": "تم إنشاء الحساب بنجاح", "redirect": "/student-dashboard"})

@app.route("/api/student/login", methods=["POST"])
def student_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    conn = get_db()
    row = conn.execute("SELECT id, password_hash FROM student_accounts WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401
    session["student_account_id"] = row["id"]
    return jsonify({"success": True, "redirect": "/student-dashboard"})

@app.route("/api/student/me", methods=["GET"])
def student_me():
    account_id = session.get("student_account_id")
    if not account_id:
        return jsonify({"error": "سجّل الدخول أولًا"}), 401
    conn = get_db()
    row = conn.execute("""SELECT s.id, s.full_name, s.username, s.class_id, c.name AS class_name
        FROM student_accounts s JOIN classes c ON c.id = s.class_id WHERE s.id = ?""", (account_id,)).fetchone()
    conn.close()
    if not row:
        session.pop("student_account_id", None)
        return jsonify({"error": "الحساب غير موجود"}), 401
    return jsonify(dict(row))

@app.route("/api/student/results", methods=["GET"])
def student_results():
    account_id = session.get("student_account_id")
    if not account_id:
        return jsonify({"error": "سجّل الدخول أولًا"}), 401
    conn = get_db()
    rows = conn.execute("""SELECT r.id, r.correct, r.wrong, r.total, r.percentage, r.created_at,
        e.title AS exam_title, c.name AS class_name
        FROM results r JOIN exams e ON e.id = r.exam_id JOIN classes c ON c.id = r.class_id
        WHERE r.student_account_id = ? ORDER BY r.id DESC""", (account_id,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/student/logout", methods=["POST"])
def student_logout():
    session.pop("student_account_id", None)
    return jsonify({"success": True, "redirect": "/student-login"})

@app.route("/exam.html")
def exam_page():
    return send_from_directory(BASE_DIR, "exam.html")

@app.route("/admin")
def admin_page():
    return send_from_directory(BASE_DIR, "admin.html")

@app.route("/admin.html")
def admin_html_page():
    return send_from_directory(BASE_DIR, "admin.html")

# ==========================================
# الصفوف
# ==========================================

@app.route("/api/classes", methods=["GET"])
def get_classes():

    conn = get_db()

    rows = conn.execute("""
        SELECT id, name
        FROM classes
        ORDER BY id
    """).fetchall()

    conn.close()

    classes = []

    for row in rows:

        classes.append({
            "id": row["id"],
            "name": row["name"]
        })

    return jsonify(classes)

# ==========================================
# امتحانات صف معين
# ==========================================

@app.route("/api/exams/<int:class_id>", methods=["GET"])
def get_exams(class_id):

    conn = get_db()

    exams = conn.execute("""
        SELECT
            e.id,
            e.title,
            e.class_id,
            e.duration,
            e.published,
            COUNT(q.id) AS question_count,
            c.name AS class_name
        FROM exams e
        LEFT JOIN questions q
            ON e.id = q.exam_id
        INNER JOIN classes c
            ON e.class_id = c.id
        WHERE e.class_id = ?
          AND e.published = 1
        GROUP BY e.id
        ORDER BY e.id DESC
    """, (class_id,)).fetchall()

    conn.close()

    result = []

    for exam in exams:

        result.append({
            "id": exam["id"],
            "title": exam["title"],
            "class_id": exam["class_id"],
            "class_name": exam["class_name"],
            "duration": exam["duration"],
            "published": exam["published"],
            "question_count": exam["question_count"]
        })

    return jsonify(result)

# ==========================================
# بيانات امتحان واحد
# ==========================================

@app.route("/api/exam/<int:exam_id>", methods=["GET"])
def get_exam(exam_id):

    conn = get_db()

    exam = conn.execute("""
        SELECT
            e.id,
            e.title,
            e.class_id,
            e.duration,
            e.published,
            c.name AS class_name
        FROM exams e
        INNER JOIN classes c
            ON e.class_id = c.id
        WHERE e.id = ?
    """, (exam_id,)).fetchone()

    if exam is None:
        conn.close()

        return jsonify({
            "error": "الامتحان غير موجود"
        }), 404

    questions = conn.execute("""
        SELECT
            id,
            question,
            question_type,
            option_a,
            option_b,
            option_c,
            option_d
        FROM questions
        WHERE exam_id = ?
        ORDER BY id
    """, (exam_id,)).fetchall()

    conn.close()

    question_list = []

    for q in questions:

        question_list.append({
            "id": q["id"],
            "question": q["question"],
            "question_type": q["question_type"],
            "option_a": q["option_a"],
            "option_b": q["option_b"],
            "option_c": q["option_c"],
            "option_d": q["option_d"]
        })

    return jsonify({
        "id": exam["id"],
        "title": exam["title"],
        "class_id": exam["class_id"],
        "class_name": exam["class_name"],
        "duration": exam["duration"],
        "published": exam["published"],
        "questions": question_list
    })

# ==========================================
# تسجيل دخول المدرس
# ==========================================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():

    data = request.get_json(silent=True) or {}
    ip = request.remote_addr or "unknown"
    now = time.monotonic()
    attempts = _admin_login_attempts[ip]
    while attempts and now - attempts[0] > 600:
        attempts.popleft()
    if len(attempts) >= 5:
        return jsonify({
            "success": False,
            "error": "محاولات كثيرة. انتظر 10 دقائق ثم حاول مرة أخرى."
        }), 429

    password = str(data.get("password", ""))

    if password == ADMIN_PASSWORD:
        attempts.clear()
        session.clear()
        session["admin_logged_in"] = True
        session.permanent = True

        return jsonify({
            "success": True,
            "message": "تم تسجيل الدخول بنجاح"
        })

    attempts.append(now)
    return jsonify({
        "success": False,
        "error": "كلمة المرور غير صحيحة"
    }), 401

# ==========================================
# تسجيل خروج المدرس
# ==========================================

@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():

    session.pop("admin_logged_in", None)

    return jsonify({
        "success": True
    })

# ==========================================
# التأكد من تسجيل الدخول
# ==========================================

@app.route("/api/admin/check", methods=["GET"])
def admin_check():

    return jsonify({
        "logged_in": bool(
            session.get("admin_logged_in")
        )
    })

# ==========================================
# جميع الامتحانات للوحة التحكم
# ==========================================

@app.route("/api/admin/exams", methods=["GET"])
@admin_required
def admin_get_exams():

    conn = get_db()

    exams = conn.execute("""
        SELECT
            e.id,
            e.title,
            e.class_id,
            e.duration,
            e.published,
            e.created_at,
            c.name AS class_name,
            COUNT(q.id) AS question_count
        FROM exams e
        INNER JOIN classes c
            ON e.class_id = c.id
        LEFT JOIN questions q
            ON e.id = q.exam_id
        GROUP BY e.id
        ORDER BY e.id DESC
    """).fetchall()

    conn.close()

    result = []

    for exam in exams:

        result.append({
            "id": exam["id"],
            "title": exam["title"],
            "class_id": exam["class_id"],
            "class_name": exam["class_name"],
            "duration": exam["duration"],
            "published": exam["published"],
            "created_at": exam["created_at"],
            "question_count": exam["question_count"]
        })

    return jsonify(result)

# ==========================================
# إنشاء امتحان
# ==========================================

@app.route("/api/admin/exams", methods=["POST"])
@admin_required
def create_exam():

    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    class_id = data.get("class_id")
    duration = data.get("duration", 30)
    published = data.get("published", False)

    if not title:
        return jsonify({
            "error": "اكتب اسم الامتحان"
        }), 400

    if not class_id:
        return jsonify({
            "error": "اختر الصف"
        }), 400

    try:
        class_id = int(class_id)
        duration = int(duration)

    except ValueError:

        return jsonify({
            "error": "بيانات غير صحيحة"
        }), 400

    conn = get_db()

    class_exists = conn.execute("""
        SELECT id
        FROM classes
        WHERE id = ?
    """, (class_id,)).fetchone()

    if not class_exists:

        conn.close()

        return jsonify({
            "error": "الصف غير موجود"
        }), 400

    cursor = conn.execute("""
        INSERT INTO exams
        (
            title,
            class_id,
            duration,
            published
        )
        VALUES (?, ?, ?, ?)
    """, (
        title,
        class_id,
        duration,
        1 if published else 0
    ))

    exam_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "id": exam_id
    })

# ==========================================
# نشر / إلغاء نشر امتحان
# ==========================================

@app.route(
    "/api/admin/exams/<int:exam_id>/publish",
    methods=["POST"]
)
@admin_required
def publish_exam(exam_id):

    data = request.get_json(silent=True) or {}

    published = data.get("published", True)

    conn = get_db()

    exam = conn.execute("""
        SELECT id
        FROM exams
        WHERE id = ?
    """, (exam_id,)).fetchone()

    if exam is None:

        conn.close()

        return jsonify({
            "error": "الامتحان غير موجود"
        }), 404

    conn.execute("""
        UPDATE exams
        SET published = ?
        WHERE id = ?
    """, (
        1 if published else 0,
        exam_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })

# ==========================================
# حذف امتحان
# ==========================================

@app.route(
    "/api/admin/exams/<int:exam_id>",
    methods=["DELETE"]
)
@admin_required
def delete_exam(exam_id):

    conn = get_db()

    conn.execute("""
        DELETE FROM questions
        WHERE exam_id = ?
    """, (exam_id,))

    conn.execute("""
        DELETE FROM results
        WHERE exam_id = ?
    """, (exam_id,))

    conn.execute("""
        DELETE FROM exams
        WHERE id = ?
    """, (exam_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })

# ==========================================
# إضافة سؤال
# ==========================================

@app.route("/api/admin/questions", methods=["POST"])
@admin_required
def create_question():

    data = request.get_json(silent=True) or {}

    exam_id = data.get("exam_id")
    question = str(data.get("question", "")).strip()

    question_type = str(
        data.get("question_type", "multiple_choice")
    ).strip().lower()

    option_a = str(data.get("option_a", "")).strip()
    option_b = str(data.get("option_b", "")).strip()
    option_c = str(data.get("option_c", "")).strip()
    option_d = str(data.get("option_d", "")).strip()

    correct_answer = str(
        data.get("correct_answer", "")
    ).strip().lower()

    if not exam_id:
        return jsonify({
            "error": "اختر الامتحان"
        }), 400

    if not question:
        return jsonify({
            "error": "اكتب السؤال"
        }), 400

    if question_type not in ["multiple_choice", "true_false"]:
        return jsonify({
            "error": "نوع السؤال غير صحيح"
        }), 400

    # سؤال صح أو خطأ
    if question_type == "true_false":

        option_a = "صح"
        option_b = "خطأ"
        option_c = ""
        option_d = ""

        if correct_answer not in ["a", "b"]:
            return jsonify({
                "error": "اختر صح أو خطأ كإجابة صحيحة"
            }), 400

    # سؤال اختيار من متعدد
    else:

        if not option_a or not option_b or not option_c or not option_d:
            return jsonify({
                "error": "اكتب جميع الاختيارات"
            }), 400

        if correct_answer not in ["a", "b", "c", "d"]:
            return jsonify({
                "error": "الإجابة الصحيحة يجب أن تكون A أو B أو C أو D"
            }), 400

    conn = get_db()

    exam = conn.execute("""
        SELECT id
        FROM exams
        WHERE id = ?
    """, (exam_id,)).fetchone()

    if exam is None:

        conn.close()

        return jsonify({
            "error": "الامتحان غير موجود"
        }), 404

    conn.execute("""
        INSERT INTO questions
        (
            exam_id,
            question,
            question_type,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        exam_id,
        question,
        question_type,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_answer
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })
# ==========================================
# عرض أسئلة امتحان في لوحة التحكم
# ==========================================

@app.route(
    "/api/admin/exams/<int:exam_id>/questions",
    methods=["GET"]
)
@admin_required
def admin_get_questions(exam_id):

    conn = get_db()

    questions = conn.execute("""
        SELECT
            id,
            exam_id,
            question,
            question_type,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        FROM questions
        WHERE exam_id = ?
        ORDER BY id
    """, (exam_id,)).fetchall()

    conn.close()

    result = []

    for q in questions:

        result.append({
            "id": q["id"],
            "exam_id": q["exam_id"],
            "question": q["question"],
            "question_type": q["question_type"],
            "option_a": q["option_a"],
            "option_b": q["option_b"],
            "option_c": q["option_c"],
            "option_d": q["option_d"],
            "correct_answer": q["correct_answer"]
        })

    return jsonify(result)

# ==========================================
# حذف سؤال
# ==========================================

@app.route(
    "/api/admin/questions/<int:question_id>",
    methods=["DELETE"]
)
@admin_required
def delete_question(question_id):

    conn = get_db()

    conn.execute("""
        DELETE FROM questions
        WHERE id = ?
    """, (question_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })

# ==========================================
# تسليم الامتحان
# ==========================================

@app.route("/api/submit-exam", methods=["POST"])
def submit_exam():

    data = request.get_json(silent=True) or {}

    student_name = str(
        data.get("student_name", "")
    ).strip()

    student_code = str(
        data.get("student_code", "")
    ).strip()

    class_id = data.get("class_id")
    exam_id = data.get("exam_id")
    answers = data.get("answers", {}) or {}

    if not student_name:
        return jsonify({
            "error": "اسم الطالب مطلوب"
        }), 400

    if not student_code:
        return jsonify({
            "error": "كود الطالب مطلوب"
        }), 400

    if not class_id or not exam_id:
        return jsonify({
            "error": "بيانات الامتحان غير مكتملة"
        }), 400

    conn = get_db()

    questions = conn.execute("""
        SELECT
            id,
            correct_answer
        FROM questions
        WHERE exam_id = ?
        ORDER BY id
    """, (exam_id,)).fetchall()

    if not questions:
        conn.close()
        return jsonify({
            "error": "هذا الامتحان لا يحتوي على أسئلة"
        }), 400

    correct = 0
    wrong = 0
    total = len(questions)

    # حساب النتيجة أولًا
    answer_rows = []

    for index, question in enumerate(questions):

        question_id = str(question["id"])

        # يدعم رقم السؤال الحقيقي، مع توافق احتياطي مع الفهرس القديم
        student_answer = answers.get(question_id)

        if student_answer is None:
            student_answer = answers.get(str(index))

        if student_answer is None:
            student_answer = answers.get(index)

        if student_answer is None:
            student_answer = ""

        student_answer = str(
            student_answer
        ).strip().lower()

        correct_answer = str(
            question["correct_answer"]
        ).strip().lower()

        is_correct = (
            student_answer == correct_answer
            and student_answer != ""
        )

        if is_correct:
            correct += 1
        else:
            wrong += 1

        answer_rows.append({
            "question_id": question["id"],
            "student_answer": student_answer,
            "correct_answer": correct_answer,
            "is_correct": 1 if is_correct else 0
        })

    percentage = 0

    if total > 0:
        percentage = round(
            (correct / total) * 100,
            2
        )

    # حفظ النتيجة
    cursor = conn.execute("""
        INSERT INTO results
        (
            student_name,
            student_code,
            class_id,
            exam_id,
            correct,
            wrong,
            total,
            percentage,
            student_account_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        student_name,
        student_code,
        class_id,
        exam_id,
        correct,
        wrong,
        total,
        percentage,
        session.get("student_account_id")
    ))

    result_id = cursor.lastrowid

    # حفظ إجابة كل سؤال
    for row in answer_rows:
        conn.execute("""
            INSERT INTO result_answers
            (
                result_id,
                question_id,
                student_answer,
                correct_answer,
                is_correct
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            result_id,
            row["question_id"],
            row["student_answer"],
            row["correct_answer"],
            row["is_correct"]
        ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "result_id": result_id,
        "correct": correct,
        "wrong": wrong,
        "total": total,
        "percentage": percentage
    })

# ==========================================
# نتائج الطلاب
# ==========================================

@app.route("/api/admin/results", methods=["GET"])
@admin_required
def admin_results():

    conn = get_db()

    results = conn.execute("""
        SELECT
            r.id,
            r.student_name,
            r.student_code,
            r.correct,
            r.wrong,
            r.total,
            r.percentage,
            r.created_at,
            r.exam_id,
            r.class_id,
            e.title AS exam_title,
            c.name AS class_name
        FROM results r
        INNER JOIN exams e
            ON r.exam_id = e.id
        INNER JOIN classes c
            ON r.class_id = c.id
        ORDER BY r.id DESC
    """).fetchall()

    conn.close()

    result = []

    for row in results:

        result.append({
            "id": row["id"],
            "student_name": row["student_name"],
            "student_code": row["student_code"],
            "correct": row["correct"],
            "wrong": row["wrong"],
            "total": row["total"],
            "percentage": row["percentage"],
            "created_at": row["created_at"],
            "exam_id": row["exam_id"],
            "class_id": row["class_id"],
            "exam_title": row["exam_title"],
            "class_name": row["class_name"]
        })

    return jsonify(result)
# ==========================================
# تفاصيل نتيجة طالب سؤالًا بسؤال
# ==========================================

@app.route(
    "/api/admin/results/<int:result_id>",
    methods=["GET"]
)
@admin_required
def admin_result_details(result_id):

    conn = get_db()

    result = conn.execute("""
        SELECT
            r.id,
            r.student_name,
            r.student_code,
            r.class_id,
            r.exam_id,
            r.correct,
            r.wrong,
            r.total,
            r.percentage,
            r.created_at,
            e.title AS exam_title,
            c.name AS class_name
        FROM results r
        INNER JOIN exams e
            ON r.exam_id = e.id
        INNER JOIN classes c
            ON r.class_id = c.id
        WHERE r.id = ?
    """, (result_id,)).fetchone()

    if result is None:
        conn.close()
        return jsonify({
            "error": "النتيجة غير موجودة"
        }), 404

    answers = conn.execute("""
        SELECT
            ra.id,
            ra.question_id,
            q.question,
            q.option_a,
            q.option_b,
            q.option_c,
            q.option_d,
            ra.student_answer,
            ra.correct_answer,
            ra.is_correct
        FROM result_answers ra
        INNER JOIN questions q
            ON ra.question_id = q.id
        WHERE ra.result_id = ?
        ORDER BY q.id
    """, (result_id,)).fetchall()

    conn.close()

    answer_list = []

    for row in answers:
        answer_list.append({
            "id": row["id"],
            "question_id": row["question_id"],
            "question": row["question"],
            "option_a": row["option_a"],
            "option_b": row["option_b"],
            "option_c": row["option_c"],
            "option_d": row["option_d"],
            "student_answer": row["student_answer"],
            "correct_answer": row["correct_answer"],
            "is_correct": bool(row["is_correct"])
        })

    return jsonify({
        "result": {
            "id": result["id"],
            "student_name": result["student_name"],
            "student_code": result["student_code"],
            "class_id": result["class_id"],
            "exam_id": result["exam_id"],
            "correct": result["correct"],
            "wrong": result["wrong"],
            "total": result["total"],
            "percentage": result["percentage"],
            "created_at": result["created_at"],
            "exam_title": result["exam_title"],
            "class_name": result["class_name"]
        },
        "answers": answer_list
    })

# ==========================================
# تعديل نتيجة طالب
# ==========================================

@app.route(
    "/api/admin/results/<int:result_id>",
    methods=["PUT"]
)
@admin_required
def admin_update_result(result_id):

    data = request.get_json(silent=True) or {}

    student_name = str(
        data.get("student_name", "")
    ).strip()

    student_code = str(
        data.get("student_code", "")
    ).strip()

    try:
        correct = int(data.get("correct", 0))
        wrong = int(data.get("wrong", 0))
        total = int(data.get("total", 0))
    except (ValueError, TypeError):
        return jsonify({
            "error": "الدرجات يجب أن تكون أرقامًا صحيحة"
        }), 400

    if not student_name:
        return jsonify({
            "error": "اسم الطالب مطلوب"
        }), 400

    if not student_code:
        return jsonify({
            "error": "كود الطالب مطلوب"
        }), 400

    if total < 0 or correct < 0 or wrong < 0:
        return jsonify({
            "error": "الدرجات لا يمكن أن تكون سالبة"
        }), 400

    if correct + wrong != total:
        return jsonify({
            "error": "مجموع الصحيح والخطأ يجب أن يساوي إجمالي الأسئلة"
        }), 400

    percentage = round(
        (correct / total) * 100,
        2
    ) if total > 0 else 0

    conn = get_db()

    existing = conn.execute("""
        SELECT id
        FROM results
        WHERE id = ?
    """, (result_id,)).fetchone()

    if existing is None:
        conn.close()
        return jsonify({
            "error": "النتيجة غير موجودة"
        }), 404

    conn.execute("""
        UPDATE results
        SET
            student_name = ?,
            student_code = ?,
            correct = ?,
            wrong = ?,
            total = ?,
            percentage = ?
        WHERE id = ?
    """, (
        student_name,
        student_code,
        correct,
        wrong,
        total,
        percentage,
        result_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "تم تعديل النتيجة بنجاح",
        "percentage": percentage
    })

# ==========================================
# حذف نتيجة طالب
# ==========================================

@app.route(
    "/api/admin/results/<int:result_id>",
    methods=["DELETE"]
)
@admin_required
def admin_delete_result(result_id):

    conn = get_db()

    existing = conn.execute("""
        SELECT id
        FROM results
        WHERE id = ?
    """, (result_id,)).fetchone()

    if existing is None:
        conn.close()
        return jsonify({
            "error": "النتيجة غير موجودة"
        }), 404

    # حذف تفاصيل الإجابات أولًا
    conn.execute("""
        DELETE FROM result_answers
        WHERE result_id = ?
    """, (result_id,))

    # ثم حذف النتيجة نفسها
    conn.execute("""
        DELETE FROM results
        WHERE id = ?
    """, (result_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "تم حذف النتيجة بنجاح"
    })

# ==========================================
# تعديل امتحان
# ==========================================

@app.route("/api/admin/exams/<int:exam_id>", methods=["PUT"])
@admin_required
def update_exam(exam_id):

    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    class_id = data.get("class_id")
    duration = data.get("duration")

    if not title:
        return jsonify({
            "error": "اكتب اسم الامتحان"
        }), 400

    if not class_id:
        return jsonify({
            "error": "اختر الصف"
        }), 400

    try:
        class_id = int(class_id)
        duration = int(duration)

    except (ValueError, TypeError):

        return jsonify({
            "error": "المدة أو الصف غير صحيح"
        }), 400

    conn = get_db()

    exam = conn.execute("""
        SELECT id
        FROM exams
        WHERE id = ?
    """, (exam_id,)).fetchone()

    if exam is None:

        conn.close()

        return jsonify({
            "error": "الامتحان غير موجود"
        }), 404

    conn.execute("""
        UPDATE exams
        SET title = ?,
            class_id = ?,
            duration = ?
        WHERE id = ?
    """, (
        title,
        class_id,
        duration,
        exam_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "تم تعديل الامتحان بنجاح"
    })

# ==========================================
# تعديل سؤال
# ==========================================

@app.route(
    "/api/admin/questions/<int:question_id>",
    methods=["PUT"]
)
@admin_required
def update_question(question_id):
    data = request.get_json(silent=True) or {}

    question = str(
        data.get("question", "")
    ).strip()

    question_type = str(
        data.get("question_type", "multiple_choice")
    ).strip().lower()

    option_a = str(
        data.get("option_a", "")
    ).strip()

    option_b = str(
        data.get("option_b", "")
    ).strip()

    option_c = str(
        data.get("option_c", "")
    ).strip()

    option_d = str(
        data.get("option_d", "")
    ).strip()

    correct_answer = str(
        data.get("correct_answer", "")
    ).strip().lower()

    if not question:
        return jsonify({
            "error": "اكتب السؤال"
        }), 400

    if question_type not in [
        "multiple_choice",
        "true_false"
    ]:
        return jsonify({
            "error": "نوع السؤال غير صحيح"
        }), 400

    # سؤال صح أو خطأ
    if question_type == "true_false":
        option_a = "صح"
        option_b = "خطأ"
        option_c = ""
        option_d = ""

        if correct_answer not in ["a", "b"]:
            return jsonify({
                "error": "اختر صح أو خطأ كإجابة صحيحة"
            }), 400

    # سؤال اختيار من متعدد
    else:
        if not option_a or not option_b or not option_c or not option_d:
            return jsonify({
                "error": "اكتب جميع الاختيارات"
            }), 400

        if correct_answer not in ["a", "b", "c", "d"]:
            return jsonify({
                "error": "الإجابة الصحيحة يجب أن تكون A أو B أو C أو D"
            }), 400

    conn = get_db()

    existing = conn.execute("""
        SELECT id
        FROM questions
        WHERE id = ?
    """, (question_id,)).fetchone()

    if existing is None:
        conn.close()

        return jsonify({
            "error": "السؤال غير موجود"
        }), 404

    conn.execute("""
        UPDATE questions
        SET
            question = ?,
            question_type = ?,
            option_a = ?,
            option_b = ?,
            option_c = ?,
            option_d = ?,
            correct_answer = ?
        WHERE id = ?
    """, (
        question,
        question_type,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_answer,
        question_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "تم تعديل السؤال بنجاح"
    })         

# ==========================================
# إدارة حسابات الطلاب - لوحة المدرس
# ==========================================
@app.route("/api/admin/students", methods=["GET"])
@admin_required
def admin_get_students():
    """إرجاع قائمة حسابات الطلاب وإحصاءاتهم دون إظهار كلمات المرور."""
    search = str(request.args.get("search", "")).strip()
    class_id = str(request.args.get("class_id", "")).strip()

    conn = get_db()
    query = """
        SELECT
            s.id, s.full_name, s.username, s.class_id, s.created_at, s.points, s.level,
            c.name AS class_name,
            COUNT(DISTINCT r.id) AS result_count,
            COALESCE(ROUND(AVG(r.percentage), 1), 0) AS average_percentage,
            MAX(r.created_at) AS last_activity
        FROM student_accounts s
        LEFT JOIN classes c ON c.id = s.class_id
        LEFT JOIN results r ON r.student_account_id = s.id
        WHERE (s.full_name LIKE ? OR s.username LIKE ?)
    """
    params = [f"%{search}%", f"%{search}%"]

    if class_id.isdigit():
        query += " AND s.class_id = ?"
        params.append(int(class_id))

    query += """
        GROUP BY s.id, s.full_name, s.username, s.class_id, s.created_at, c.name
        ORDER BY s.id DESC
    """

    rows = conn.execute(query, params).fetchall()
    total_accounts = conn.execute("SELECT COUNT(*) FROM student_accounts").fetchone()[0]
    conn.close()

    return jsonify({
        "students": [dict(row) for row in rows],
        "total_accounts": total_accounts,
        "shown": len(rows)
    })

@app.route("/api/admin/students/<int:student_id>", methods=["PUT"])
@admin_required
def admin_update_student(student_id):
    data = request.get_json(silent=True) or {}
    full_name = str(data.get("full_name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    try:
        class_id = int(data.get("class_id"))
        points = max(0, int(data.get("points", 0)))
        level = max(1, int(data.get("level", 1)))
    except (TypeError, ValueError):
        return jsonify({"error":"تحقق من الصف والنقاط والمستوى"}), 400
    if len(full_name) < 3 or len(username) < 4:
        return jsonify({"error":"اسم الطالب أو الكود غير صحيح"}), 400
    conn = get_db()
    if not conn.execute("SELECT id FROM classes WHERE id=?", (class_id,)).fetchone():
        conn.close(); return jsonify({"error":"الصف الدراسي غير صحيح"}), 400
    try:
        cur = conn.execute("UPDATE student_accounts SET full_name=?, username=?, class_id=?, points=?, level=? WHERE id=?",
                           (full_name, username, class_id, points, level, student_id))
        if not cur.rowcount:
            conn.close(); return jsonify({"error":"الطالب غير موجود"}), 404
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"error":"كود الطالب مستخدم بالفعل"}), 409
    conn.close()
    return jsonify({"success":True, "message":"تم حفظ تعديلات الطالب"})

@app.route("/api/leaderboard", methods=["GET"])
def public_leaderboard():
    conn = get_db()
    rows = conn.execute("""
        SELECT s.id, s.full_name, s.username, s.points, s.level, c.name AS class_name
        FROM student_accounts s JOIN classes c ON c.id=s.class_id
        ORDER BY s.points DESC, s.level DESC, s.full_name ASC LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify({"leaderboard":[dict(r) for r in rows]})

@app.route("/api/admin/students/<int:student_id>", methods=["GET"])
@admin_required
def admin_get_student_profile(student_id):
    """ملف تفصيلي لحساب طالب، متاح للمدرس المسجل دخوله فقط."""
    conn = get_db()
    student = conn.execute("""
        SELECT s.id, s.full_name, s.username, s.class_id, s.created_at,
               c.name AS class_name,
               COUNT(DISTINCT r.id) AS result_count,
               COALESCE(ROUND(AVG(r.percentage), 1), 0) AS average_percentage,
               MAX(r.created_at) AS last_activity
        FROM student_accounts s
        LEFT JOIN classes c ON c.id = s.class_id
        LEFT JOIN results r ON r.student_account_id = s.id
        WHERE s.id = ?
        GROUP BY s.id, s.full_name, s.username, s.class_id, s.created_at, c.name
    """, (student_id,)).fetchone()

    if not student:
        conn.close()
        return jsonify({"error": "حساب الطالب غير موجود"}), 404

    results = conn.execute("""
        SELECT r.id, r.student_name, r.student_code, r.correct, r.wrong,
               r.total, r.percentage, r.created_at,
               e.title AS exam_title, c.name AS class_name
        FROM results r
        LEFT JOIN exams e ON e.id = r.exam_id
        LEFT JOIN classes c ON c.id = r.class_id
        WHERE r.student_account_id = ?
        ORDER BY r.created_at DESC, r.id DESC
    """, (student_id,)).fetchall()
    conn.close()

    return jsonify({
        "student": dict(student),
        "results": [dict(row) for row in results]
    })

# ==========================================
# تصدير كشف الطلاب والدرجات إلى CSV متوافق مع Excel
# ==========================================
@app.route("/api/admin/export/students.csv", methods=["GET"])
@admin_required
def admin_export_students_csv():
    """تصدير حسابات الطلاب ونتائجهم، بما فيها النتائج القديمة غير المرتبطة بحساب."""
    conn = get_db()
    students = conn.execute("""
        SELECT s.id, s.full_name, s.username, c.name AS class_name, s.created_at
        FROM student_accounts s
        LEFT JOIN classes c ON c.id = s.class_id
        ORDER BY s.id ASC
    """).fetchall()
    results = conn.execute("""
        SELECT r.id, r.student_account_id, r.student_name, r.student_code,
               c.name AS class_name, e.title AS exam_title, r.correct, r.wrong,
               r.total, r.percentage, r.created_at
        FROM results r
        LEFT JOIN classes c ON c.id = r.class_id
        LEFT JOIN exams e ON e.id = r.exam_id
        ORDER BY r.created_at ASC, r.id ASC
    """).fetchall()
    conn.close()

    students_by_id = {row["id"]: row for row in students}
    results_by_student = {}
    legacy_results = []
    for result in results:
        account_id = result["student_account_id"]
        if account_id is None or account_id not in students_by_id:
            legacy_results.append(result)
        else:
            results_by_student.setdefault(account_id, []).append(result)

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "معرّف الحساب", "اسم الطالب", "اسم المستخدم", "الصف الدراسي",
        "تاريخ التسجيل", "اسم الامتحان", "الإجابات الصحيحة",
        "الإجابات الخاطئة", "إجمالي الأسئلة", "النسبة المئوية", "تاريخ النتيجة",
        "كود الطالب في النتيجة", "معرّف النتيجة"
    ])

    for student in students:
        student_results = results_by_student.get(student["id"], [])
        if not student_results:
            writer.writerow([student["id"], student["full_name"], student["username"],
                             student["class_name"] or "", student["created_at"] or "",
                             "لا توجد نتائج", "", "", "", "", "", "", ""])
            continue
        for result in student_results:
            writer.writerow([student["id"], student["full_name"], student["username"],
                             student["class_name"] or result["class_name"] or "",
                             student["created_at"] or "", result["exam_title"] or "امتحان غير معروف",
                             result["correct"], result["wrong"], result["total"],
                             result["percentage"], result["created_at"] or "",
                             result["student_code"] or "", result["id"]])

    # تضمين النتائج القديمة التي لم تُربط بحساب طالب بدل إسقاطها من التقرير.
    for result in legacy_results:
        writer.writerow(["", result["student_name"] or "", "", result["class_name"] or "",
                         "", result["exam_title"] or "امتحان غير معروف", result["correct"],
                         result["wrong"], result["total"], result["percentage"],
                         result["created_at"] or "", result["student_code"] or "", result["id"]])

    csv_data = "\ufeff" + output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=bariq_nour_students_grades.csv"}
    )

# ==========================================
# تشغيل الموقع
# ==========================================

if __name__ == "__main__":

    init_database()

    print("=" * 50)
    print("موقع أستاذ أنور أبو ستيت")
    print("الدراسات الاجتماعية")
    print("رابط الموقع: http://127.0.0.1:5000")
    print("لوحة التحكم: http://127.0.0.1:5000/admin")
    print("كلمة مرور لوحة التحكم محفوظة في private_settings.py")
    print("=" * 50)

app.run(
    host="0.0.0.0",
    port=5000,
    debug=False
)

