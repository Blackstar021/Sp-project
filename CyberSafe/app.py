import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import date, timedelta
from functools import wraps
from pathlib import Path
from markupsafe import Markup
from urllib.parse import unquote, urlsplit

import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from lesson_seeds import LESSON_PAGES

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; env vars can be set directly
    def load_dotenv(_path):
        return False

ROOT = Path(__file__).resolve().parent
# Local development secrets: load .env from the app folder and the project root
# (Vercel ignores these files; set environment variables in the project dashboard).
load_dotenv(ROOT / ".env")
load_dotenv(ROOT.parent / ".env")
IS_VERCEL = bool(os.environ.get("VERCEL"))
# Vercel's serverless filesystem is read-only except for /tmp.
DEFAULT_DATABASE = Path("/tmp/cybersafe.sqlite3") if IS_VERCEL else ROOT / "cybersafe.sqlite3"
DATABASE = Path(os.environ.get("CYBERSAFE_DATABASE", DEFAULT_DATABASE))
FAILURES = defaultdict(deque)
FAILURES_LOCK = threading.Lock()
QUIZ_LOGIN_MESSAGE = (
    "Please sign in or create an account to take the quiz. "
    "Your scores will be saved to your dashboard."
)


def is_safe_redirect(target):
    """Only allow relative paths on this site as post-authentication destinations."""
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        return False
    decoded = unquote(target)
    if "\\" in decoded or decoded.startswith("//"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in decoded):
        return False
    parsed = urlsplit(decoded)
    return not parsed.scheme and not parsed.netloc and parsed.path.startswith("/")

MODULES = [
    ("phishing", "Phishing", "Recognize deceptive messages before they steal your information.",
     "Phishing impersonates trusted people or organizations to trick you into sharing information or opening a harmful link. It can arrive by email, text, social media, QR code, or phone call.",
     ["A school account warning asks you to sign in through an unfamiliar link.", "A delivery text demands a small fee through a shortened URL."],
     ["Pause when a message creates urgency.", "Check the sender and link independently.", "Use a known address or contact the organization directly."]),
    ("online-scams", "Online Scams", "Spot fake offers, impersonation, and manipulation.",
     "Scammers use false promises, urgency, or secrecy to get money, account access, or personal data. Verify unexpected requests using a separate trusted channel.",
     ["A giveaway asks for a payment or password to claim a prize.", "A buyer sends a fake payment screenshot and asks you to refund money."],
     ["Be skeptical of surprise prizes and urgent payment requests.", "Never share passwords or sign-in codes.", "Ask a trusted adult before sending money."]),
    ("password-security", "Password Security", "Build stronger account security with unique passwords and MFA.",
     "Use a long, unique passphrase for each account. Reusing passwords means one breach can put other accounts at risk. A password manager can create and remember unique passwords; enable multi-factor authentication when available.",
     ["Use a different password for school email and gaming.", "Turn on an authenticator app or security key."],
     ["Use long, unique passwords.", "Never share passwords or one-time codes.", "Enable multi-factor authentication."]),
    ("personal-information", "Protecting Personal Information", "Share thoughtfully and control who can see your information.",
     "Location, school, contact details, schedules, and photos can identify or locate you. Review privacy settings and app permissions, and think about the audience before posting.",
     ["A photo reveals your school name in the background.", "A public post announces when your family is away."],
     ["Share only what is needed.", "Check audience and location settings.", "Ask before posting someone else's image or details."]),
    ("ethical-internet-use", "Ethical Internet Use", "Be respectful, responsible, and lawful online.",
     "Respect people's privacy, creators' work, and system rules. Never access accounts or systems without permission. Report harmful behavior or security concerns through appropriate channels.",
     ["Ask before sharing a classmate's private message.", "Privately report a security concern to authorized school IT."],
     ["Treat people online with respect.", "Never access systems without permission.", "Credit creators and report concerns responsibly."]),
]

QUESTION_SEEDS = {
    "phishing": [
        ("A message says your school account closes in 10 minutes. What should you do?", ["Click immediately", "Open the school site with a known bookmark", "Reply with your password", "Forward it to everyone"], 1, "Urgency is a pressure tactic. Use a known, official route."),
        ("Which sender detail should you inspect?", ["Full email address and domain", "Logo color", "Time of day", "Number of exclamation marks"], 0, "Display names and logos can be copied; inspect the full sender address."),
        ("A friend sends an unexpected sign-in link. What is safest?", ["Enter your password", "Verify with your friend through another channel", "Share it publicly", "Disable spam filtering"], 1, "Your friend's account may be compromised. Verify surprising requests separately."),
        ("How should you visit your school account?", ["Unexpected message link", "Shortened URL", "Known official address or bookmark", "Reply asking for a link"], 2, "A known address avoids lookalike links."),
        ("You entered your password on a suspicious page. What now?", ["Ignore it", "Tell a trusted adult and change it through the official site", "Reuse it elsewhere", "Send the link to friends"], 1, "Act promptly and change the exposed password through the legitimate site."),
    ],
    "online-scams": [
        ("A prize requires a fee through an unfamiliar link. What should you do?", ["Pay quickly", "Avoid the link and verify the offer", "Send your password", "Share your address"], 1, "Unexpected prizes with fees and urgency are common scam signals."),
        ("A buyer says they overpaid and wants a refund. What is safest?", ["Refund immediately", "Verify with your payment provider directly", "Share a login code", "Trust a screenshot"], 1, "Screenshots can be faked; check your account and contact the provider."),
        ("A stranger asks you to keep your chat secret. What should you do?", ["Keep it secret", "Stop and talk to a trusted adult", "Send a photo", "Move apps"], 1, "Requests for secrecy can be a warning sign."),
        ("Which is a common scam sign?", ["A request you can verify", "Urgent gift-card payment demand", "Known school portal", "Device privacy reminder"], 1, "Gift cards are hard to reverse and commonly requested by scammers."),
        ("You sent money to a suspected scammer. What next?", ["Wait", "Tell a trusted adult and contact your bank/payment provider", "Pay a recovery fee", "Send more details"], 1, "Promptly contacting your provider may help secure the account."),
    ],
    "password-security": [
        ("Which password strategy is safest?", ["Pet name everywhere", "Long unique passphrase per account", "Add 1 to an old password", "Share it with a friend"], 1, "Long, unique passwords limit guessing and breach impact."),
        ("What can a password manager do?", ["Reuse one password", "Create and store unique passwords", "Remove device security needs", "Share passwords publicly"], 1, "A password manager helps you use unique passwords."),
        ("What should you do with a one-time sign-in code?", ["Share it with support", "Keep it private and use it only in the service you initiated", "Post it in chat", "Save publicly"], 1, "A one-time code can grant account access."),
        ("What does multi-factor authentication add?", ["Another proof of identity", "A second username", "A public profile", "A longer email"], 0, "MFA requires another proof beyond your password."),
        ("A reused password may have leaked. What should you do?", ["Change it wherever reused", "Wait", "Change one character", "Post it with a warning"], 0, "Replace reused passwords with distinct ones and enable MFA."),
    ],
    "personal-information": [
        ("Before posting a vacation photo, what should you consider?", ["If it reveals location or an empty home", "Brightness", "Hashtags", "Filter"], 0, "Photos and captions may reveal location and schedules."),
        ("A simple app requests contacts and location. What should you do?", ["Allow all", "Deny unnecessary access and review permissions", "Publish contacts", "Install more apps"], 1, "Grant only permissions needed for the app's purpose."),
        ("Which is personal information?", ["Home address and daily schedule", "Weather report", "Fictional character", "Science fact"], 0, "Address and routine can help identify or locate you."),
        ("A classmate asks you to post their photo. What is respectful?", ["Post everywhere", "Get permission and choose the audience", "Add their schedule", "Tag their home"], 1, "Ask permission before sharing someone's image."),
        ("Which is a good privacy habit?", ["Review app permissions regularly", "Accept every tracking request", "Use public Wi-Fi for everything", "Reuse profile details"], 0, "Regular reviews limit unnecessary access."),
    ],
    "ethical-internet-use": [
        ("A classmate left their account logged in. What should you do?", ["Read messages", "Log them out or tell them privately", "Post a joke", "Change their password"], 1, "Respect their privacy; do not access the account."),
        ("You use another person's image in a project. What should you do?", ["Claim it", "Credit the creator and follow usage terms", "Remove attribution", "Sell copies"], 1, "Credit creators and follow permission/license terms."),
        ("You find a school website security issue. What is responsible?", ["Test on other users", "Privately report to authorized IT", "Publish exploit details", "Change records"], 1, "Do not access or modify data; report it privately."),
        ("How should you respond to online harassment?", ["Join in", "Do not amplify it; report and seek trusted help", "Retaliate with private details", "Create a fake account"], 1, "Do not escalate harm; report and ask for help."),
        ("Which respects privacy?", ["Forward private chat", "Ask before sharing a photo or message", "Guess a password", "Post someone's location"], 1, "Get permission before sharing personal content."),
    ],
}

TIPS = [
    ("Messages", "Pause before opening unexpected links or attachments."),
    ("Messages", "Verify urgent requests through a known contact method."),
    ("Accounts", "Use a unique password for each account and enable MFA."),
    ("Accounts", "Never share passwords or one-time verification codes."),
    ("Privacy", "Review profile visibility, location sharing, and app permissions."),
    ("Privacy", "Think about what a photo background or caption reveals."),
    ("Devices", "Install updates from official sources and use a screen lock."),
    ("Respect", "Ask before sharing someone else's photo or private message."),
    ("Respect", "Report threats and scams to a trusted adult or school IT."),
]


def connect(database=DATABASE):
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def render_lesson_content(content):
    """Render a small Markdown subset while escaping all author-provided HTML."""
    def inline_format(text):
        escaped = html.escape(text, quote=False)
        return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)

    blocks = []
    paragraph = []
    list_open = False
    table_open = False

    def close_list():
        nonlocal list_open
        if list_open:
            blocks.append("</ul>")
            list_open = False

    def close_table():
        nonlocal table_open
        if table_open:
            blocks.append("</tbody></table></div>")
            table_open = False

    def flush_paragraph():
        if paragraph:
            blocks.append(f"<p>{' '.join(inline_format(line) for line in paragraph)}</p>")
            paragraph.clear()

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            close_list()
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                continue
            if not table_open:
                blocks.append('<div class="lesson-table-wrap"><table class="lesson-table"><tbody>')
                table_open = True
            blocks.append("<tr>" + "".join(f"<td>{inline_format(cell)}</td>" for cell in cells) + "</tr>")
        else:
            close_table()
            if not stripped:
                flush_paragraph()
                close_list()
            elif stripped.startswith("## "):
                flush_paragraph()
                close_list()
                blocks.append(f"<h2>{inline_format(stripped[3:])}</h2>")
            elif stripped.startswith("### "):
                flush_paragraph()
                close_list()
                blocks.append(f"<h3>{inline_format(stripped[4:])}</h3>")
            elif stripped.startswith(("- ", "* ")):
                flush_paragraph()
                if not list_open:
                    blocks.append("<ul>")
                    list_open = True
                blocks.append(f"<li>{inline_format(stripped[2:])}</li>")
            else:
                close_list()
                paragraph.append(stripped)
    flush_paragraph()
    close_list()
    close_table()
    return Markup("".join(blocks))


def initialize_database(database=DATABASE):
    database.parent.mkdir(parents=True, exist_ok=True)
    db = connect(database)
    try:
        with db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS modules (
                    id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
                    summary TEXT NOT NULL, lesson TEXT NOT NULL, examples TEXT NOT NULL,
                    takeaways TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tips (
                    id INTEGER PRIMARY KEY, category TEXT NOT NULL, content TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY, module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    prompt TEXT NOT NULL, options TEXT NOT NULL,
                    answer INTEGER NOT NULL CHECK(answer BETWEEN 0 AND 3), explanation TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quiz_scores (
                    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    score INTEGER NOT NULL, total INTEGER NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS progress (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(user_id, module_id)
                );
                CREATE TABLE IF NOT EXISTS quiz_attempts (
                    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    score INTEGER NOT NULL, total_questions INTEGER NOT NULL,
                    percentage REAL NOT NULL, taken_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS module_pages (
                    id INTEGER PRIMARY KEY,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    page_number INTEGER NOT NULL CHECK(page_number IN (1, 2)),
                    heading TEXT NOT NULL,
                    content TEXT NOT NULL,
                    UNIQUE(module_id, page_number)
                );
                CREATE TABLE IF NOT EXISTS lesson_progress (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(user_id, module_id)
                );
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "role" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
            if db.execute("SELECT COUNT(*) FROM modules").fetchone()[0] == 0:
                for slug, title, summary, lesson, examples, takeaways in MODULES:
                    db.execute(
                        "INSERT INTO modules (slug,title,summary,lesson,examples,takeaways) VALUES (?,?,?,?,?,?)",
                        (slug, title, summary, lesson, json.dumps(examples), json.dumps(takeaways)),
                    )
            for slug, seeded in QUESTION_SEEDS.items():
                module = db.execute("SELECT id FROM modules WHERE slug=?", (slug,)).fetchone()
                if module and not db.execute("SELECT 1 FROM questions WHERE module_id=? LIMIT 1", (module["id"],)).fetchone():
                    for prompt, options, answer, explanation in seeded:
                        db.execute(
                            "INSERT INTO questions (module_id,prompt,options,answer,explanation) VALUES (?,?,?,?,?)",
                            (module["id"], prompt, json.dumps(options), answer, explanation),
                        )
            for slug, pages in LESSON_PAGES.items():
                module = db.execute("SELECT id FROM modules WHERE slug=?", (slug,)).fetchone()
                if module and not db.execute(
                        "SELECT 1 FROM module_pages WHERE module_id=? LIMIT 1", (module["id"],)
                ).fetchone():
                        db.executemany(
                            "INSERT INTO module_pages (module_id,page_number,heading,content) VALUES (?,?,?,?)",
                            [
                                (module["id"], page_number, page["heading"], page["content"])
                                for page_number, page in enumerate(pages, start=1)
                            ],
                        )
            if db.execute("SELECT COUNT(*) FROM tips").fetchone()[0] == 0:
                db.executemany("INSERT INTO tips (category,content) VALUES (?,?)", TIPS)
            admin_email = os.environ.get("CYBERSAFE_ADMIN_EMAIL", "").strip().lower()
            admin_password = os.environ.get("CYBERSAFE_ADMIN_PASSWORD", "")
            if admin_email and admin_password and not db.execute(
                "SELECT 1 FROM users WHERE email=?", (admin_email,)
            ).fetchone():
                db.execute(
                    "INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')",
                    ("CyberSafe Admin", admin_email, generate_password_hash(admin_password)),
                )
    finally:
        db.close()


def create_app():
    app = Flask(__name__)
    secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
    if not secret_key:
        # Fall back to a per-process key so the app still starts instead of
        # crashing with FUNCTION_INVOCATION_FAILED. Set SECRET_KEY in the
        # Vercel project settings to keep sessions stable across cold starts.
        secret_key = secrets.token_hex(32)
        if IS_VERCEL:
            app.logger.warning(
                "SECRET_KEY is not set. Using a random key; users will be logged "
                "out on each cold start. Set SECRET_KEY in the Vercel environment."
            )
    app.config.update(
        SECRET_KEY=secret_key,
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=IS_VERCEL,
    )
    initialize_database()

    def db():
        if "db" not in g:
            g.db = connect(DATABASE)
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def check_csrf():
        provided = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not provided or not expected or not hmac.compare_digest(provided, expected):
            abort(400, "Invalid form token. Reload the page and try again.")

    def login_required(view):
        """Require a signed-in account and remember the page the student requested."""
        @wraps(view)
        def wrapped(*args, **kwargs):
            if user() is None:
                target = request.full_path.rstrip("?")
                flash(QUIZ_LOGIN_MESSAGE, "info")
                return redirect(url_for("login", next=target))
            return view(*args, **kwargs)
        return wrapped

    def user():
        identity = session.get("user_id")
        return db().execute("SELECT id,name,email,role FROM users WHERE id=?", (identity,)).fetchone() if identity else None

    def admin_required():
        current = user()
        if current is None:
            return redirect(url_for("login", next=request.path))
        if current["role"] != "admin":
            abort(403)
        return None

    @app.context_processor
    def context():
        return {"current_user": user(), "csrf_token": csrf_token()}

    def module_data(row):
        if not row:
            return None
        item = dict(row)
        item["examples"] = json.loads(item["examples"])
        item["takeaways"] = json.loads(item["takeaways"])
        item["question_count"] = db().execute("SELECT COUNT(*) FROM questions WHERE module_id=?", (item["id"],)).fetchone()[0]
        return item

    @app.cli.command("seed-db")
    def seed_db_command():
        initialize_database()
        click.echo(f"SQLite database ready: {DATABASE}")

    @app.cli.command("create-admin")
    def create_admin():
        name = click.prompt("Admin name").strip()
        email = click.prompt("Admin email").strip().lower()
        password = click.prompt("Admin password", hide_input=True, confirmation_prompt=True)
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 12:
            raise click.ClickException("Enter a name, valid email, and password with at least 12 characters.")
        if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise click.ClickException("That email is already registered.")
        db().execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')",
                     (name, email, generate_password_hash(password)))
        db().commit()
        click.echo(f"Admin account created: {email}")

    @app.get("/")
    def index():
        rows = db().execute("SELECT * FROM modules ORDER BY title").fetchall()
        account = user()
        lessons_read = {
            row["module_id"]
            for row in db().execute(
                "SELECT module_id FROM lesson_progress WHERE user_id=?",
                (account["id"],),
            )
        } if account else set()
        return render_template(
            "index.html",
            modules=[module_data(row) for row in rows],
            lessons_read=lessons_read,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        next_target = request.values.get("next", "")
        safe_next = next_target if is_safe_redirect(next_target) else ""
        if request.method == "GET":
            return render_template("register.html", error=None, next_url=safe_next)
        check_csrf()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or len(name) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 8 or password != request.form.get("confirm_password"):
            return render_template(
                "register.html",
                error="Enter a valid name and email, use an 8-character password, and confirm it.",
                next_url=safe_next,
            ), 400
        try:
            db().execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)",
                         (name, email, generate_password_hash(password)))
            db().commit()
        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                error="Unable to create an account with those details.",
                next_url=safe_next,
            ), 400
        account = db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        session.clear()
        session["user_id"] = account["id"]
        flash("Account created. You can now log in.", "success")
        return redirect(safe_next or url_for("dashboard"))

    @app.get("/forgot-password")
    def forgot_password():
        return render_template("forgot_password.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_target = request.values.get("next", "")
        safe_next = next_target if is_safe_redirect(next_target) else ""
        if request.method == "GET":
            return render_template("login.html", error=None, next_url=safe_next)
        check_csrf()
        client = request.remote_addr or "unknown"
        now = time.monotonic()
        with FAILURES_LOCK:
            attempts = FAILURES[client]
            while attempts and attempts[0] < now - 900:
                attempts.popleft()
            limited = len(attempts) >= 5
        email = request.form.get("email", "").strip().lower()
        account = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if limited or account is None or not check_password_hash(account["password_hash"], request.form.get("password", "")):
            if not limited:
                with FAILURES_LOCK:
                    FAILURES[client].append(now)
            return render_template(
                "login.html",
                error="Invalid email or password",
                next_url=safe_next,
            ), 429 if limited else 401
        with FAILURES_LOCK:
            FAILURES.pop(client, None)
        session.clear()
        session["user_id"] = account["id"]
        session.permanent = request.form.get("remember") == "on"
        target = safe_next
        if not target:
            target = url_for("admin") if account["role"] == "admin" else url_for("dashboard")
        return redirect(target)

    @app.post("/logout")
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("index"))

    @app.get("/modules")
    def modules():
        rows = db().execute("SELECT * FROM modules ORDER BY title").fetchall()
        account = user()
        lessons_read = {
            row["module_id"]
            for row in db().execute(
                "SELECT module_id FROM lesson_progress WHERE user_id=?",
                (account["id"],),
            )
        } if account else set()
        return render_template(
            "modules.html",
            modules=[module_data(row) for row in rows],
            lessons_read=lessons_read,
        )

    @app.get("/modules/<slug>")
    def module(slug):
        row = db().execute("SELECT * FROM modules WHERE slug=?", (slug,)).fetchone()
        if row is None:
            abort(404)
        return render_template("module.html", module=module_data(row))

    @app.get("/learn/<slug>")
    def learn(slug):
        module_row = db().execute("SELECT * FROM modules WHERE slug=?", (slug,)).fetchone()
        if module_row is None:
            abort(404)
        try:
            page_number = int(request.args.get("page", "1"))
        except ValueError:
            abort(404)
        if page_number not in (1, 2):
            abort(404)
        lesson_page = db().execute(
            "SELECT heading,content FROM module_pages WHERE module_id=? AND page_number=?",
            (module_row["id"], page_number),
        ).fetchone()
        if lesson_page is None:
            abort(404)

        account = user()
        lesson_completed = False
        if account:
            lesson_completed = db().execute(
                "SELECT 1 FROM lesson_progress WHERE user_id=? AND module_id=?",
                (account["id"], module_row["id"]),
            ).fetchone() is not None
            if page_number == 2 and not lesson_completed:
                db().execute(
                    "INSERT OR IGNORE INTO lesson_progress (user_id,module_id) VALUES (?,?)",
                    (account["id"], module_row["id"]),
                )
                db().commit()
                lesson_completed = True

        return render_template(
            "lesson.html",
            module=module_data(module_row),
            lesson_page=lesson_page,
            page_number=page_number,
            lesson_completed=lesson_completed,
            lesson_html=render_lesson_content(lesson_page["content"]),
        )

    @app.get("/tips")
    def tips():
        rows = db().execute("SELECT category,content FROM tips ORDER BY category,id").fetchall()
        categories = {}
        for item in rows:
            categories.setdefault(item["category"], []).append(item["content"])
        return render_template("tips.html", categories=categories)

    @app.route("/quiz/<slug>", methods=["GET", "POST"])
    @login_required
    def quiz(slug):
        row = db().execute("SELECT * FROM modules WHERE slug=?", (slug,)).fetchone()
        if row is None:
            abort(404)
        item = module_data(row)
        questions = db().execute("SELECT * FROM questions WHERE module_id=? ORDER BY id", (item["id"],)).fetchall()
        if request.method == "GET":
            return render_template("quiz.html", module=item, questions=[dict(q, options=json.loads(q["options"])) for q in questions])
        check_csrf()
        review, score = [], 0
        for question in questions:
            try:
                selected = int(request.form.get(f"q_{question['id']}", "-1"))
            except ValueError:
                selected = -1
            correct = selected == question["answer"]
            score += int(correct)
            review.append({"prompt": question["prompt"], "options": json.loads(question["options"]),
                           "selected": selected, "answer": question["answer"],
                           "explanation": question["explanation"], "correct": correct})
        account = user()
        db().execute("INSERT INTO quiz_scores (user_id,module_id,score,total) VALUES (?,?,?,?)",
                     (account["id"], item["id"], score, len(questions)))
        db().execute("INSERT INTO quiz_attempts (user_id,module_id,score,total_questions,percentage,taken_at) VALUES (?,?,?,?,?,?)",
                     (account["id"], item["id"], score, len(questions), (score / len(questions)) * 100, time.strftime('%Y-%m-%d %H:%M:%S')))
        db().execute("INSERT INTO progress (user_id,module_id) VALUES (?,?) ON CONFLICT(user_id,module_id) DO UPDATE SET completed_at=CURRENT_TIMESTAMP",
                     (account["id"], item["id"]))
        db().commit()
        return render_template("results.html", module=item, review=review, score=score,
                               total=len(questions), saved=True)

    @app.get("/activity/phishing")
    def phishing_activity():
        return render_template("activity.html")

    @app.get("/dashboard")
    @login_required
    def dashboard():
        account = user()
        scores = db().execute("""SELECT quiz_scores.*,modules.title,modules.slug
            FROM quiz_scores JOIN modules ON modules.id=quiz_scores.module_id
            WHERE quiz_scores.user_id=? ORDER BY quiz_scores.id DESC LIMIT 25""", (account["id"],)).fetchall()
        done = {r["module_id"] for r in db().execute("SELECT module_id FROM progress WHERE user_id=?", (account["id"],))}
        lessons_read = {
            r["module_id"]
            for r in db().execute("SELECT module_id FROM lesson_progress WHERE user_id=?", (account["id"],))
        }
        rows = db().execute("SELECT * FROM modules ORDER BY title").fetchall()
        latest_scores = {}
        for score in db().execute(
            "SELECT module_id,score,total FROM quiz_scores WHERE user_id=? ORDER BY id DESC",
            (account["id"],),
        ):
            latest_scores.setdefault(score["module_id"], dict(score))
        module_items = [module_data(row) for row in rows]
        for item in module_items:
            item["latest_score"] = latest_scores.get(item["id"])
        return render_template("dashboard.html", user=account, scores=scores,
                               completed=done, lessons_read=lessons_read,
                               modules=module_items)

    @app.route("/admin/users", methods=["GET"])
    def admin_users():
        denied = admin_required()
        if denied:
            return denied
        users = db().execute("SELECT id,name,email,role,created_at FROM users ORDER BY id").fetchall()
        return render_template("admin_users.html", users=users)

    @app.post("/admin/users/<int:user_id>/edit")
    def edit_user(user_id):
        check_csrf()
        denied = admin_required()
        if denied:
            return denied
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "")
        password = request.form.get("password", "")
        if not name or len(name) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or role not in {"student", "admin"}:
            flash("Enter a valid name, email, and role.", "error")
            return redirect(url_for("admin_users"))
        if password and len(password) < 8:
            flash("A reset password must contain at least 8 characters.", "error")
            return redirect(url_for("admin_users"))
        connection = db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            actor_id = user()["id"]
            target = connection.execute("SELECT id,role FROM users WHERE id=?", (user_id,)).fetchone()
            if target is None:
                flash("That account no longer exists.", "error")
            elif target["id"] == actor_id and role != "admin":
                flash("You cannot remove your own administrator role.", "error")
            elif target["role"] == "admin" and role != "admin" and connection.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin'"
            ).fetchone()[0] <= 1:
                flash("The site must keep at least one administrator.", "error")
            elif connection.execute("SELECT 1 FROM users WHERE email=? AND id!=?", (email,user_id)).fetchone():
                flash("That email address is already in use.", "error")
            elif password:
                connection.execute("UPDATE users SET name=?,email=?,role=?,password_hash=? WHERE id=?",
                                   (name,email,role,generate_password_hash(password),user_id))
                flash("User account updated.", "success")
            else:
                connection.execute("UPDATE users SET name=?,email=?,role=? WHERE id=?", (name,email,role,user_id))
                flash("User account updated.", "success")
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            app.logger.exception("User update constraint error")
            flash("That email address is already in use.", "error")
        except Exception:
            connection.rollback()
            app.logger.exception("User update failed")
            flash("The user account could not be updated.", "error")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/delete")
    def delete_user(user_id):
        check_csrf()
        denied = admin_required()
        if denied:
            return denied
        connection = db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            actor_id = user()["id"]
            target = connection.execute("SELECT id,role FROM users WHERE id=?", (user_id,)).fetchone()
            if target is None:
                flash("That account no longer exists.", "error")
            elif target["id"] == actor_id:
                flash("You cannot delete your own account.", "error")
            elif target["role"] == "admin" and connection.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin'"
            ).fetchone()[0] <= 1:
                flash("The site must keep at least one administrator.", "error")
            else:
                connection.execute("DELETE FROM quiz_scores WHERE user_id=?", (user_id,))
                connection.execute("DELETE FROM progress WHERE user_id=?", (user_id,))
                connection.execute("DELETE FROM users WHERE id=?", (user_id,))
                flash("User account deleted.", "success")
            connection.commit()
        except Exception:
            connection.rollback()
            app.logger.exception("User delete failed")
            flash("The user account could not be deleted.", "error")
        return redirect(url_for("admin_users"))

    def quiz_result_filters():
        conditions = []
        params = []
        module_slug = request.args.get("module", "").strip()
        search = request.args.get("search", "").strip()
        date_start = request.args.get("date_start", "").strip()
        date_end = request.args.get("date_end", "").strip()

        if module_slug:
            conditions.append("m.slug = ?")
            params.append(module_slug)
        if search:
            conditions.append("(LOWER(u.name) LIKE LOWER(?) OR LOWER(u.email) LIKE LOWER(?))")
            params.extend((f"%{search}%", f"%{search}%"))
        for value in (date_start, date_end):
            if value:
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    abort(400, "Dates must use the YYYY-MM-DD format.")
                try:
                    date.fromisoformat(value)
                except ValueError:
                    abort(400, "Dates must use the YYYY-MM-DD format.")
        if date_start and date_end and date_start > date_end:
            abort(400, "The start date must not be after the end date.")
        if date_start:
            conditions.append("qa.taken_at >= ?")
            params.append(f"{date_start} 00:00:00")
        if date_end:
            conditions.append("qa.taken_at < ?")
            params.append(f"{date.fromisoformat(date_end) + timedelta(days=1)} 00:00:00")

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        return where_clause, params, module_slug, search, date_start, date_end

    def quiz_results_admin_only():
        account = user()
        if account is None or account["role"] != "admin":
            abort(403)

    @app.get("/admin/quiz-results")
    def admin_quiz_results():
        quiz_results_admin_only()
        connection = db()
        where_clause, params, module_slug, search, date_start, date_end = quiz_result_filters()
        page = max(request.args.get("page", 1, type=int) or 1, 1)
        per_page = 10
        joins = "FROM quiz_attempts qa JOIN users u ON qa.user_id = u.id JOIN modules m ON qa.module_id = m.id"

        total_attempts = connection.execute(
            f"SELECT COUNT(*) {joins} {where_clause}", params
        ).fetchone()[0]
        summary = connection.execute(
            f"""SELECT COALESCE(AVG(qa.percentage), 0),
                       COUNT(DISTINCT qa.user_id)
                {joins} {where_clause}""",
            params,
        ).fetchone()
        total_pages = max((total_attempts + per_page - 1) // per_page, 1)
        page = min(page, total_pages)
        offset = (page - 1) * per_page
        attempts = connection.execute(
            f"""SELECT qa.id, qa.user_id AS student_id, qa.score, qa.total_questions,
                       qa.percentage, qa.taken_at, u.name AS student_name,
                       u.email AS student_email, m.title AS module_title
                {joins} {where_clause}
                ORDER BY qa.taken_at DESC, qa.id DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()
        modules = connection.execute("SELECT id, slug, title FROM modules ORDER BY title").fetchall()

        return render_template(
            "admin_quiz_results.html",
            attempts=attempts,
            total_attempts=total_attempts,
            avg_score=round(summary[0], 1),
            students_count=summary[1],
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            modules=modules,
            selected_module=module_slug,
            search=search,
            date_start=date_start,
            date_end=date_end,
            csrf_token=csrf_token(),
        )

    @app.route("/admin/quiz-results/view/<int:student_id>", methods=["GET"])
    def admin_quiz_view_student(student_id):
        quiz_results_admin_only()
        connection = db()
        student = connection.execute(
            "SELECT id, name, email FROM users WHERE id=?", (student_id,)
        ).fetchone()
        if student is None:
            abort(404)
        attempts = connection.execute(
            "SELECT qa.score, qa.total_questions, qa.percentage, qa.taken_at, m.title AS module_title "
            "FROM quiz_attempts qa "
            "JOIN modules m ON qa.module_id = m.id "
            "WHERE qa.user_id = ? "
            "ORDER BY qa.taken_at DESC, qa.id DESC",
            (student_id,),
        ).fetchall()
        average = connection.execute(
            "SELECT COALESCE(AVG(percentage), 0) FROM quiz_attempts WHERE user_id=?",
            (student_id,),
        ).fetchone()[0]
        return render_template(
            "admin_quiz_view_student.html",
            attempts=attempts,
            student=student,
            avg_score=round(average, 1),
        )

    @app.route("/admin/quiz-results/export", methods=["GET"])
    def admin_quiz_results_export():
        import csv
        import io
        from flask import Response

        quiz_results_admin_only()
        connection = db()
        where_clause, params, *_filters = quiz_result_filters()
        attempts = connection.execute(
            f"""SELECT u.name, u.email, m.title AS module_title, qa.score,
                       qa.total_questions, qa.percentage, qa.taken_at
                FROM quiz_attempts qa
                JOIN users u ON qa.user_id = u.id
                JOIN modules m ON qa.module_id = m.id
                {where_clause}
                ORDER BY qa.taken_at DESC, qa.id DESC""",
            params,
        ).fetchall()

        def csv_safe(value):
            text = str(value)
            formula_value = text.lstrip(" \t\r\n")
            return f"'{text}" if formula_value.startswith(("=", "+", "-", "@")) else text

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Student name", "Email", "Module", "Score", "Percentage", "Date taken"])
        for a in attempts:
            writer.writerow([
                csv_safe(a["name"]),
                csv_safe(a["email"]),
                csv_safe(a["module_title"]),
                f"{a['score']}/{a['total_questions']}",
                csv_safe(f"{a['percentage']:.1f}%"),
                csv_safe(a["taken_at"]),
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=quiz_results.csv"},
        )

    @app.route("/admin", methods=["GET", "POST"])
    def admin():
        denied = admin_required()
        if denied:
            return denied
        if request.method == "POST":
            check_csrf()
            action = request.form.get("action", "")
            try:
                if action == "module_save":
                    title = request.form.get("title", "").strip()
                    slug = request.form.get("slug", "").strip().lower()
                    if not slug:
                        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
                    summary = request.form.get("summary", "").strip()
                    lesson = request.form.get("lesson", "").strip()
                    examples = [x.strip() for x in request.form.get("examples", "").splitlines() if x.strip()]
                    takeaways = [x.strip() for x in request.form.get("takeaways", "").splitlines() if x.strip()]
                    module_id = request.form.get("id", "").strip()
                    page_data = [
                        (
                            request.form.get(f"page_{page_number}_heading", "").strip(),
                            request.form.get(f"page_{page_number}_content", "").strip(),
                        )
                        for page_number in (1, 2)
                    ]
                    if module_id and (not module_id.isdecimal() or int(module_id) < 1):
                        flash("The module id is invalid.", "error")
                        return redirect(url_for("admin"))
                    if (
                        not title or len(title) > 120 or not summary or not lesson
                        or any(not heading or not content for heading, content in page_data)
                        or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug)
                    ):
                        flash("Enter a title, description, lesson, two page headings and contents, and URL-safe unique slug.", "error")
                    elif db().execute("SELECT 1 FROM modules WHERE slug=? AND id != COALESCE(NULLIF(?,''),'0')", (slug,module_id)).fetchone():
                        flash("That module URL is already in use.", "error")
                    elif module_id:
                        db().execute("UPDATE modules SET slug=?,title=?,summary=?,lesson=?,examples=?,takeaways=? WHERE id=?",
                                     (slug,title,summary,lesson,json.dumps(examples),json.dumps(takeaways),module_id))
                        db().executemany(
                            """INSERT INTO module_pages (module_id,page_number,heading,content)
                               VALUES (?,?,?,?)
                               ON CONFLICT(module_id,page_number)
                               DO UPDATE SET heading=excluded.heading,content=excluded.content""",
                            [
                                (module_id, page_number, heading, content)
                                for page_number, (heading, content) in enumerate(page_data, start=1)
                            ],
                        )
                        db().commit()
                        flash("Module saved.", "success")
                    else:
                        db().execute("INSERT INTO modules (slug,title,summary,lesson,examples,takeaways) VALUES (?,?,?,?,?,?)",
                                     (slug,title,summary,lesson,json.dumps(examples),json.dumps(takeaways)))
                        new_module_id = db().execute("SELECT last_insert_rowid()").fetchone()[0]
                        db().executemany(
                            "INSERT INTO module_pages (module_id,page_number,heading,content) VALUES (?,?,?,?)",
                            [
                                (new_module_id, page_number, heading, content)
                                for page_number, (heading, content) in enumerate(page_data, start=1)
                            ],
                        )
                        db().commit()
                        flash("Module saved.", "success")
                elif action == "module_delete":
                    db().execute("DELETE FROM modules WHERE id=?", (request.form.get("id", ""),))
                    db().commit()
                    flash("Module deleted.", "success")
                elif action == "tip_save":
                    tip_id, category, content = request.form.get("id", ""), request.form.get("category", "").strip(), request.form.get("content", "").strip()
                    if not category or not content:
                        flash("Enter a category and tip.", "error")
                    elif tip_id:
                        db().execute("UPDATE tips SET category=?,content=? WHERE id=?", (category,content,tip_id))
                        db().commit()
                        flash("Tip updated.", "success")
                    else:
                        db().execute("INSERT INTO tips (category,content) VALUES (?,?)", (category,content))
                        db().commit()
                        flash("Tip added.", "success")
                elif action == "tip_delete":
                    db().execute("DELETE FROM tips WHERE id=?", (request.form.get("id", ""),))
                    db().commit()
                    flash("Tip deleted.", "success")
                elif action == "question_save":
                    qid, module_id = request.form.get("id", ""), request.form.get("module_id", "")
                    prompt = request.form.get("prompt", "").strip()
                    options = [request.form.get(f"option_{i}", "").strip() for i in range(4)]
                    explanation = request.form.get("explanation", "").strip()
                    try:
                        answer = int(request.form.get("answer", "-1"))
                    except ValueError:
                        answer = -1
                    if not prompt or not explanation or any(not x for x in options) or answer not in range(4):
                        flash("Enter a question, four answers, a correct answer, and explanation.", "error")
                    elif qid:
                        db().execute("UPDATE questions SET module_id=?,prompt=?,options=?,answer=?,explanation=? WHERE id=?",
                                     (module_id,prompt,json.dumps(options),answer,explanation,qid))
                        db().commit()
                        flash("Question updated.", "success")
                    else:
                        db().execute("INSERT INTO questions (module_id,prompt,options,answer,explanation) VALUES (?,?,?,?,?)",
                                     (module_id,prompt,json.dumps(options),answer,explanation))
                        db().commit()
                        flash("Question added.", "success")
                elif action == "question_delete":
                    db().execute("DELETE FROM questions WHERE id=?", (request.form.get("id", ""),))
                    db().commit()
                    flash("Question deleted.", "success")
                else:
                    abort(400)
            except sqlite3.IntegrityError:
                db().rollback()
                app.logger.exception("Admin content database constraint failure")
                flash("Could not save this content. Check for duplicate or missing fields.", "error")
            except Exception:
                db().rollback()
                app.logger.exception("Admin content update failed")
                flash("Could not save this content due to a server error.", "error")
            return redirect(url_for("admin"))

        modules = [module_data(r) for r in db().execute("SELECT * FROM modules ORDER BY title")]
        for item in modules:
            pages = db().execute(
                "SELECT page_number,heading,content FROM module_pages WHERE module_id=? ORDER BY page_number",
                (item["id"],),
            ).fetchall()
            item["lesson_pages"] = {
                page["page_number"]: dict(page) for page in pages
            }
        users = db().execute("SELECT id,name,email,role,created_at FROM users ORDER BY id").fetchall()
        tips = db().execute("SELECT * FROM tips ORDER BY category,id").fetchall()
        questions = []
        for q in db().execute("SELECT questions.*,modules.title AS module_title FROM questions JOIN modules ON modules.id=questions.module_id ORDER BY modules.title,questions.id"):
            questions.append(dict(q, options=json.loads(q["options"])))
        return render_template("admin.html", modules=modules, users=users, tips=tips, questions=questions)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="Administrator access is required."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="We couldn't find that page."), 404

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
