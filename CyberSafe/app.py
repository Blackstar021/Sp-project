import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("CYBERSAFE_DATABASE", BASE_DIR / "cybersafe.sqlite3"))
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
login_attempts = defaultdict(deque)
login_attempts_lock = threading.Lock()

MODULE_SEEDS = [
    {
        "slug": "phishing",
        "title": "Phishing",
        "summary": "Recognize deceptive messages before they steal your information.",
        "lesson": "Phishing is a social-engineering attack that impersonates a trusted person or organization. Messages may create urgency, ask for passwords, or direct you to a convincing but fake sign-in page. Attackers can use email, text messages, social media, QR codes, or phone calls.",
        "examples": [
            "A message claiming your school account will be closed unless you sign in immediately.",
            "A delivery text that asks for a small fee through an unfamiliar link.",
            "A social media message from a friend whose account may have been taken over.",
        ],
        "takeaways": [
            "Pause when a message pressures you to act quickly.",
            "Check the sender and destination address independently.",
            "Visit the official site or contact the organization using known details.",
            "Report suspicious messages to a trusted adult or school IT team.",
        ],
    },
    {
        "slug": "online-scams",
        "title": "Online Scams",
        "summary": "Spot fake offers, impersonation, and manipulation online.",
        "lesson": "Online scams use deception to obtain money, account access, or personal data. Scammers may impersonate a company, a public figure, a classmate, or a romantic interest. They often combine an exciting promise with urgency or secrecy.",
        "examples": [
            "A too-good-to-be-true giveaway that requires a payment or account password.",
            "A buyer who sends a fake payment screenshot and asks you to refund an overpayment.",
            "A stranger asking you to keep a conversation secret and move to another app.",
        ],
        "takeaways": [
            "Be skeptical of unexpected prizes, discounts, and urgent payment requests.",
            "Never share one-time login codes or passwords with another person.",
            "Verify requests through a separate, trusted contact method.",
            "Ask a trusted adult for help before sending money or private images.",
        ],
    },
    {
        "slug": "password-security",
        "title": "Password Security",
        "summary": "Create memorable, unique passwords and secure your accounts.",
        "lesson": "A long, unique passphrase is difficult to guess and limits damage if another service is breached. Reusing passwords lets an attacker try a leaked password on other accounts. A password manager can create and remember unique passwords. Add multi-factor authentication (MFA) whenever it is available.",
        "examples": [
            "Use a different password for school email and gaming accounts.",
            "Turn on an authenticator app or security key for important accounts.",
            "Use a password manager rather than saving passwords in a shared document.",
        ],
        "takeaways": [
            "Use long, unique passwords or passphrases for every account.",
            "Never share passwords or MFA codes.",
            "Enable MFA and keep account recovery details current.",
            "Change a password promptly if you think it has been exposed.",
        ],
    },
    {
        "slug": "personal-information",
        "title": "Protecting Personal Information",
        "summary": "Make thoughtful choices about what you share and who can see it.",
        "lesson": "Personal information includes your location, school, contact details, schedule, photos, and account identifiers. Small details can be combined to identify or impersonate someone. Review privacy settings, limit app permissions, and think about the audience before posting.",
        "examples": [
            "A photo background reveals the name of your school or your home address.",
            "A public post announces that your family is away from home.",
            "A quiz app requests access to contacts and location when it does not need them.",
        ],
        "takeaways": [
            "Share only information needed for a clear purpose.",
            "Check audience, location, and privacy settings before posting.",
            "Review app permissions and remove access you do not need.",
            "Ask permission before posting someone else's image or information.",
        ],
    },
    {
        "slug": "ethical-internet-use",
        "title": "Ethical Internet Use",
        "summary": "Be respectful, responsible, and lawful in digital spaces.",
        "lesson": "Ethical internet use means respecting people, privacy, ownership, and rules online. Do not access accounts or systems without permission, even as a joke. Credit creators, protect private information, and respond constructively to harmful behavior.",
        "examples": [
            "Ask before sharing a classmate's photo or private message.",
            "Cite the creator when you use their work for a school project.",
            "Report a security weakness privately to the responsible organization.",
        ],
        "takeaways": [
            "Treat people online with the same respect as in person.",
            "Never access, alter, or disrupt an account or system without permission.",
            "Respect copyright and give credit to creators.",
            "Report harmful content or security issues through appropriate channels.",
        ],
    },
]

QUESTION_SEEDS = {
    "phishing": [
        ("A message says your school account closes in 10 minutes and includes a sign-in link. What is the safest next step?", ["Click quickly before time runs out", "Open the school site using a saved bookmark and check there", "Reply with your password to confirm your identity", "Forward it to all your classmates"], 1, "Urgency is a common pressure tactic. Use a known, official route instead of the message link."),
        ("Which sender detail is most useful to inspect?", ["The sender's full email address and domain", "The logo's colors", "How many exclamation marks it uses", "Whether it arrived in the morning"], 0, "Display names and logos can be copied; the full sender address gives you more context."),
        ("A friend sends an unexpected link asking you to vote and sign in. What should you do?", ["Enter your school password", "Check with your friend through another channel", "Share the link publicly", "Disable your spam filter"], 1, "A friend's account may be compromised. Verify surprising requests separately."),
        ("What is a safer way to reach a bank or school account?", ["Use the link in an unexpected message", "Search for a shortened link", "Type the official address or use a saved bookmark", "Reply and ask the sender to resend"], 2, "A known address or bookmark avoids lookalike and shortened links."),
        ("You entered your password on a page that now seems fake. What should you do first?", ["Ignore it if nothing happened", "Tell a trusted adult or IT contact and change it through the official site", "Send the page to friends", "Reuse the password somewhere else"], 1, "Act promptly: contact support and change the exposed password using the legitimate site."),
    ],
    "online-scams": [
        ("A stranger offers a free game console if you pay a small shipping fee through a link. What is the best response?", ["Pay quickly before the offer expires", "Avoid the link and verify the offer through an official source", "Send your account password", "Share your home address"], 1, "Unexpected prizes with fees and urgency are common scam signals."),
        ("Someone says they accidentally sent extra money and asks you to return it. What should you do?", ["Send a refund immediately", "Verify the transaction directly with the payment provider", "Share a one-time code", "Post the payment screenshot"], 1, "Screenshots can be faked. Check your account and contact the provider through its official app/site."),
        ("A person online asks you to keep your conversation secret from trusted adults. What is a safe response?", ["Keep it secret to be polite", "Stop responding and talk to a trusted adult", "Send personal photos", "Move to a private app"], 1, "Requests for secrecy can be a warning sign; trusted adults can help you stay safe."),
        ("Which is a common sign of a scam?", ["A request you can verify independently", "An unexpected demand for gift cards or crypto", "A known teacher using the school portal", "A privacy reminder from your device"], 1, "Scammers often request payment methods that are difficult to reverse or trace."),
        ("You think you sent money to a scammer. What should you do?", ["Delete all messages and wait", "Tell a trusted adult and contact your bank or payment service promptly", "Pay a second fee to recover it", "Give the scammer more details"], 1, "Quickly contacting your financial provider may help secure the account or transaction."),
    ],
    "password-security": [
        ("Which password strategy is safest?", ["Use your pet's name everywhere", "Use a long, unique passphrase for each account", "Add 1 to your old password", "Share passwords with a close friend"], 1, "Long, unique passwords limit guessing and prevent one breach from exposing other accounts."),
        ("Why use a password manager?", ["It makes every password the same", "It can create and store unique passwords securely", "It removes the need to protect your device", "It shares passwords automatically"], 1, "A reputable password manager helps you use strong, unique passwords without memorizing each one."),
        ("What should you do with a one-time sign-in code?", ["Share it with someone claiming to be support", "Keep it private and enter it only into the service you initiated", "Post it in a class chat", "Save it in a public note"], 1, "A one-time code can give someone access to your account. Legitimate support should not ask you to disclose it."),
        ("What does multi-factor authentication add?", ["A second proof of identity beyond your password", "A second username", "A public profile", "A longer email address"], 0, "MFA requires another proof, making stolen passwords less useful on their own."),
        ("You learn a password you reused may have leaked. What should you do?", ["Change it on every account where it was reused, starting with important accounts", "Wait until someone logs in", "Change only one character", "Post a warning with the password included"], 0, "Change reused passwords to distinct, strong values and turn on MFA."),
    ],
    "personal-information": [
        ("Before posting a vacation photo, what should you consider?", ["Whether it reveals your location or that your home is empty", "Whether the image is bright enough", "How many hashtags it has", "Whether it has a filter"], 0, "Photos and captions can reveal location and schedules to a broad audience."),
        ("An app requests your contacts and location for a simple flashlight feature. What should you do?", ["Allow everything", "Deny permissions that are not needed and review privacy settings", "Share your contacts publicly", "Install a second flashlight app"], 1, "Grant only permissions needed for the app's purpose."),
        ("Which is personal information?", ["Your home address and daily schedule", "A public weather report", "A fictional character's name", "A general science fact"], 0, "Address and routine can help identify or locate you."),
        ("A classmate asks you to post their photo. What is a respectful choice?", ["Post it to every account", "Get clear permission and choose an appropriate audience", "Add their school schedule", "Tag their home location"], 1, "Ask permission before sharing others' images or details."),
        ("What is a good privacy habit?", ["Review app permissions and account visibility regularly", "Use public Wi-Fi for every private task without care", "Accept every tracking request", "Use the same profile details everywhere"], 0, "Regular reviews help limit unnecessary access and exposure."),
    ],
    "ethical-internet-use": [
        ("You discover a classmate left their account logged in. What should you do?", ["Read their messages", "Log them out or tell them privately without accessing the account", "Post from their account as a joke", "Change their password"], 1, "Respect their privacy and do not access their account without permission."),
        ("You include an image made by someone else in a project. What should you do?", ["Claim you created it", "Give appropriate credit and follow its usage terms", "Remove the creator's name", "Sell copies without permission"], 1, "Credit creators and follow the license or permission requirements."),
        ("You find a security flaw in a school website. What is the responsible action?", ["Test it on other users", "Privately report it to the authorized school IT contact", "Publish details and exploit it", "Change student records to prove it"], 1, "Do not access or modify data. Report the concern privately through an authorized channel."),
        ("How should you respond to harmful behavior online?", ["Join in so you fit in", "Avoid amplifying it and report or seek help from a trusted adult", "Share private information about the person", "Create a fake account to retaliate"], 1, "Do not escalate harm. Report it and ask for help when needed."),
        ("Which action respects another person's privacy?", ["Forward a private chat without consent", "Ask before sharing a classmate's photo or message", "Guess a friend's password", "Post someone's location"], 1, "Get permission before sharing personal content or identifying information."),
    ],
}

TIP_SEEDS = [
    ("Messages", "Pause before clicking unexpected links or attachments."),
    ("Messages", "Verify urgent requests with the person or organization through a known contact method."),
    ("Accounts", "Use a unique password for every account and enable multi-factor authentication."),
    ("Accounts", "Never share passwords or one-time verification codes."),
    ("Privacy", "Review profile visibility, location sharing, and app permissions regularly."),
    ("Privacy", "Think about what a photo background or caption might reveal."),
    ("Devices", "Install updates from official sources and use a screen lock."),
    ("Respect", "Ask before sharing someone else's photo, message, or personal details."),
    ("Respect", "Report threats, scams, or security concerns to a trusted adult or school IT team."),
]


def get_connection(database=DATABASE):
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database=DATABASE):
    database.parent.mkdir(parents=True, exist_ok=True)
    db = get_connection(database)
    try:
        with db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'student',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    lesson TEXT NOT NULL,
                    examples TEXT NOT NULL,
                    takeaways TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS tips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    prompt TEXT NOT NULL,
                    options TEXT NOT NULL,
                    answer INTEGER NOT NULL CHECK(answer BETWEEN 0 AND 3),
                    explanation TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quiz_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    score INTEGER NOT NULL,
                    total INTEGER NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS progress (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, module_id)
                );
                """
            )
            user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "role" not in user_columns:
                db.execute(
                    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'"
                )

            if db.execute("SELECT COUNT(*) FROM modules").fetchone()[0] == 0:
                for module in MODULE_SEEDS:
                    db.execute(
                        """
                        INSERT INTO modules (slug, title, summary, lesson, examples, takeaways)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            module["slug"],
                            module["title"],
                            module["summary"],
                            module["lesson"],
                            json.dumps(module["examples"]),
                            json.dumps(module["takeaways"]),
                        ),
                    )

            for slug, seed_questions in QUESTION_SEEDS.items():
                module = db.execute(
                    "SELECT id FROM modules WHERE slug = ?", (slug,)
                ).fetchone()
                if module and db.execute(
                    "SELECT COUNT(*) FROM questions WHERE module_id = ?",
                    (module["id"],),
                ).fetchone()[0] == 0:
                    for prompt, options, answer, explanation in seed_questions:
                        db.execute(
                            """
                            INSERT INTO questions (module_id, prompt, options, answer, explanation)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (module["id"], prompt, json.dumps(options), answer, explanation),
                        )

            if db.execute("SELECT COUNT(*) FROM tips").fetchone()[0] == 0:
                db.executemany(
                    "INSERT INTO tips (category, content) VALUES (?, ?)", TIP_SEEDS
                )

            admin_email = os.environ.get("CYBERSAFE_ADMIN_EMAIL", "").strip().lower()
            admin_password = os.environ.get("CYBERSAFE_ADMIN_PASSWORD", "")
            if bool(admin_email) != bool(admin_password):
                raise ValueError(
                    "Set both CYBERSAFE_ADMIN_EMAIL and CYBERSAFE_ADMIN_PASSWORD "
                    "to seed an administrator account."
                )
            if admin_email and admin_password:
                if (
                    len(admin_password) < 12
                    or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", admin_email)
                ):
                    raise ValueError(
                        "CYBERSAFE_ADMIN_EMAIL must be valid and "
                        "CYBERSAFE_ADMIN_PASSWORD must be at least 12 characters."
                    )
                existing_admin = db.execute(
                    "SELECT role FROM users WHERE email = ?", (admin_email,)
                ).fetchone()
                if existing_admin is None:
                    db.execute(
                        """
                        INSERT INTO users (name, email, password_hash, role)
                        VALUES (?, ?, ?, 'admin')
                        """,
                        (
                            "CyberSafe Admin",
                            admin_email,
                            generate_password_hash(admin_password),
                        ),
                    )
                elif existing_admin["role"] != "admin":
                    raise ValueError(
                        "The configured admin email is already a student account. "
                        "Use the create-admin command with another email."
                    )
    finally:
        db.close()


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() == "true",
    )

    def get_db():
        if "db" not in g:
            g.db = get_connection(DATABASE)
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def get_csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def csrf_is_valid():
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        return bool(submitted and expected and hmac.compare_digest(submitted, expected))

    def require_csrf():
        if not csrf_is_valid():
            abort(400, description="Your session expired. Please reload and try again.")

    def login_is_rate_limited(client_key):
        now = time.monotonic()
        cutoff = now - LOGIN_ATTEMPT_WINDOW_SECONDS
        with login_attempts_lock:
            attempts = login_attempts[client_key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            return len(attempts) >= MAX_LOGIN_ATTEMPTS

    def record_login_failure(client_key):
        now = time.monotonic()
        cutoff = now - LOGIN_ATTEMPT_WINDOW_SECONDS
        with login_attempts_lock:
            attempts = login_attempts[client_key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            attempts.append(now)

    def clear_login_failures(client_key):
        with login_attempts_lock:
            login_attempts.pop(client_key, None)

    def current_user():
        identity = session.get("user")
        if not identity:
            return None
        user = get_db().execute(
            "SELECT id, name, email, role FROM users WHERE id = ?", (identity["id"],)
        ).fetchone()
        if user is None:
            session.clear()
            return None
        return user

    def require_admin():
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if user["role"] != "admin":
            abort(403)
        return None

    def module_rows():
        return get_db().execute("SELECT * FROM modules ORDER BY title").fetchall()

    def build_module(row):
        if row is None:
            return None
        module = dict(row)
        module["examples"] = json.loads(module["examples"])
        module["takeaways"] = json.loads(module["takeaways"])
        module["question_count"] = get_db().execute(
            "SELECT COUNT(*) FROM questions WHERE module_id = ?", (module["id"],)
        ).fetchone()[0]
        return module

    def module_by_slug(slug):
        return build_module(
            get_db().execute("SELECT * FROM modules WHERE slug = ?", (slug,)).fetchone()
        )

    @app.context_processor
    def inject_template_state():
        return {"current_user": current_user(), "csrf_token": get_csrf_token()}

    @app.cli.command("init-db")
    def init_db_command():
        initialize_database()
        click.echo(f"CyberSafe database initialized at {DATABASE}")

    @app.cli.command("create-admin")
    def create_admin():
        name = click.prompt("Admin name").strip()
        email = click.prompt("Admin email").strip().lower()
        password = click.prompt(
            "Admin password", hide_input=True, confirmation_prompt=True
        )
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise click.ClickException("Enter a name and a valid email address.")
        if len(password) < 12:
            raise click.ClickException("Admin passwords must be at least 12 characters.")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise click.ClickException("An account already uses that email address.")
        db.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (name, email, generate_password_hash(password)),
        )
        db.commit()
        click.echo(f"Administrator account created for {email}.")

    @app.route("/")
    def index():
        modules = [build_module(row) for row in module_rows()]
        return render_template("index.html", modules=modules)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if request.args.get("registered"):
                flash("Your account is ready. Please log in.")
            return render_template("login.html", error=None, email="")
        require_csrf()
        client_key = request.remote_addr or "unknown"
        if login_is_rate_limited(client_key):
            return render_template(
                "login.html",
                error="Invalid email or password",
                email=request.form.get("email", ""),
            ), 429
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, name, email, password_hash, role FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            record_login_failure(client_key)
            return render_template(
                "login.html",
                error="Invalid email or password",
                email=request.form.get("email", ""),
            ), 401
        clear_login_failures(client_key)
        remember = request.form.get("remember") == "on"
        session.clear()
        session.permanent = remember
        session["user"] = {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
        }
        get_csrf_token()
        destination = request.args.get("next", "")
        if not destination.startswith("/") or destination.startswith("//"):
            destination = (
                url_for("admin_panel") if user["role"] == "admin"
                else url_for("dashboard")
            )
        return redirect(destination)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", error=None, name="", email="")
        require_csrf()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if (
            not name
            or len(name) > 100
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
            or len(password) < 8
            or password != confirmation
        ):
            error = (
                "Enter a name, valid email, password of at least 8 characters, "
                "and matching confirmation."
            )
            return render_template(
                "register.html", error=error, name=name, email=email
            ), 400
        try:
            get_db().execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password)),
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                error="Unable to create an account with those details.",
                name=name,
                email=email,
            ), 400
        return redirect(url_for("login", registered="1"))

    @app.route("/forgot-password")
    def forgot_password():
        return render_template("forgot_password.html")

    @app.route("/modules")
    def modules():
        return render_template(
            "modules.html", modules=[build_module(row) for row in module_rows()]
        )

    @app.route("/modules/<slug>")
    def module_detail(slug):
        module = module_by_slug(slug)
        if module is None:
            abort(404)
        return render_template("module_detail.html", module=module)

    @app.route("/tips")
    def tips():
        rows = get_db().execute(
            "SELECT category, content FROM tips ORDER BY category, id"
        ).fetchall()
        categorized = {}
        for row in rows:
            categorized.setdefault(row["category"], []).append(row["content"])
        return render_template("tips.html", categories=categorized)

    @app.route("/quiz/<slug>", methods=["GET", "POST"])
    def quiz(slug):
        module = module_by_slug(slug)
        if module is None:
            abort(404)
        rows = get_db().execute(
            "SELECT * FROM questions WHERE module_id = ? ORDER BY id", (module["id"],)
        ).fetchall()
        if not rows:
            abort(404, description="This module does not have quiz questions yet.")
        questions = []
        for row in rows:
            question = dict(row)
            question["options"] = json.loads(question["options"])
            questions.append(question)
        if request.method == "GET":
            return render_template("quiz.html", module=module, questions=questions)
        require_csrf()
        review = []
        score = 0
        for question in questions:
            submitted = request.form.get(f"q_{question['id']}", "")
            try:
                selected = int(submitted)
            except ValueError:
                selected = -1
            correct = selected == question["answer"]
            if correct:
                score += 1
            review.append(
                {
                    "prompt": question["prompt"],
                    "options": question["options"],
                    "selected": selected,
                    "answer": question["answer"],
                    "explanation": question["explanation"],
                    "correct": correct,
                }
            )
        user = current_user()
        if user is not None:
            get_db().execute(
                "INSERT INTO quiz_scores (user_id, module_id, score, total) VALUES (?, ?, ?, ?)",
                (user["id"], module["id"], score, len(questions)),
            )
            get_db().execute(
                """
                INSERT INTO progress (user_id, module_id) VALUES (?, ?)
                ON CONFLICT(user_id, module_id) DO UPDATE SET completed_at = CURRENT_TIMESTAMP
                """,
                (user["id"], module["id"]),
            )
            get_db().commit()
        return render_template(
            "quiz_results.html",
            module=module,
            review=review,
            score=score,
            total=len(questions),
            saved=user is not None,
        )

    @app.route("/activity/phishing")
    def phishing_activity():
        return render_template("phishing_activity.html")

    @app.route("/dashboard")
    def dashboard():
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        scores = get_db().execute(
            """
            SELECT quiz_scores.score, quiz_scores.total, quiz_scores.completed_at,
                   modules.title, modules.slug
            FROM quiz_scores JOIN modules ON modules.id = quiz_scores.module_id
            WHERE quiz_scores.user_id = ? ORDER BY quiz_scores.completed_at DESC, quiz_scores.id DESC
            LIMIT 20
            """,
            (user["id"],),
        ).fetchall()
        completed = {
            row["module_id"] for row in get_db().execute(
                "SELECT module_id FROM progress WHERE user_id = ?", (user["id"],)
            ).fetchall()
        }
        return render_template(
            "dashboard.html",
            user=user,
            scores=scores,
            modules=[build_module(row) for row in module_rows()],
            completed=completed,
        )

    @app.route("/admin", methods=["GET", "POST"])
    def admin_panel():
        if request.method == "POST":
            require_csrf()
            denied = require_admin()
            if denied:
                return denied
            db = get_db()
            action = request.form.get("action", "")
            if action == "account_create":
                name = request.form.get("name", "").strip()
                email = request.form.get("email", "").strip().lower()
                password = request.form.get("password", "")
                if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 8:
                    flash("Enter a name, valid email, and password with at least 8 characters.", "error")
                else:
                    try:
                        db.execute(
                            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                            (name, email, generate_password_hash(password)),
                        )
                        db.commit()
                        flash("Student account created.", "success")
                    except sqlite3.IntegrityError:
                        flash("An account already uses that email address.", "error")
            elif action == "module_save":
                module_id = request.form.get("id", "").strip()
                slug = request.form.get("slug", "").strip().lower()
                title = request.form.get("title", "").strip()
                summary = request.form.get("summary", "").strip()
                lesson = request.form.get("lesson", "").strip()
                examples = [item.strip() for item in request.form.get("examples", "").splitlines() if item.strip()]
                takeaways = [item.strip() for item in request.form.get("takeaways", "").splitlines() if item.strip()]
                if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) or not title or not summary or not lesson:
                    flash("Modules need a valid URL slug, title, summary, and lesson.", "error")
                else:
                    try:
                        values = (slug, title, summary, lesson, json.dumps(examples), json.dumps(takeaways))
                        if module_id:
                            db.execute(
                                "UPDATE modules SET slug=?, title=?, summary=?, lesson=?, examples=?, takeaways=? WHERE id=?",
                                (*values, module_id),
                            )
                        else:
                            db.execute(
                                "INSERT INTO modules (slug, title, summary, lesson, examples, takeaways) VALUES (?, ?, ?, ?, ?, ?)",
                                values,
                            )
                        db.commit()
                        flash("Module saved.", "success")
                    except sqlite3.IntegrityError:
                        flash("That module URL slug is already in use.", "error")
            elif action == "module_delete":
                db.execute("DELETE FROM modules WHERE id = ?", (request.form.get("id", ""),))
                db.commit()
                flash("Module deleted.", "success")
            elif action == "tip_save":
                tip_id = request.form.get("id", "").strip()
                category = request.form.get("category", "").strip()
                content = request.form.get("content", "").strip()
                if not category or not content:
                    flash("Tips need both a category and content.", "error")
                elif tip_id:
                    db.execute("UPDATE tips SET category = ?, content = ? WHERE id = ?", (category, content, tip_id))
                    db.commit()
                    flash("Tip updated.", "success")
                else:
                    db.execute("INSERT INTO tips (category, content) VALUES (?, ?)", (category, content))
                    db.commit()
                    flash("Tip added.", "success")
            elif action == "tip_delete":
                db.execute("DELETE FROM tips WHERE id = ?", (request.form.get("id", ""),))
                db.commit()
                flash("Tip deleted.", "success")
            elif action == "question_save":
                question_id = request.form.get("id", "").strip()
                module_id = request.form.get("module_id", "").strip()
                prompt = request.form.get("prompt", "").strip()
                options = [request.form.get(f"option_{index}", "").strip() for index in range(4)]
                explanation = request.form.get("explanation", "").strip()
                try:
                    answer = int(request.form.get("answer", ""))
                except ValueError:
                    answer = -1
                if not prompt or not explanation or any(not option for option in options) or answer not in range(4):
                    flash("Questions require a prompt, four options, a correct answer, and an explanation.", "error")
                else:
                    try:
                        if question_id:
                            db.execute(
                                "UPDATE questions SET module_id=?, prompt=?, options=?, answer=?, explanation=? WHERE id=?",
                                (module_id, prompt, json.dumps(options), answer, explanation, question_id),
                            )
                        else:
                            db.execute(
                                "INSERT INTO questions (module_id, prompt, options, answer, explanation) VALUES (?, ?, ?, ?, ?)",
                                (module_id, prompt, json.dumps(options), answer, explanation),
                            )
                        db.commit()
                        flash("Quiz question saved.", "success")
                    except sqlite3.IntegrityError:
                        flash("Choose an existing module for the question.", "error")
            elif action == "question_delete":
                db.execute("DELETE FROM questions WHERE id = ?", (request.form.get("id", ""),))
                db.commit()
                flash("Quiz question deleted.", "success")
            else:
                abort(400, description="Unknown administration action.")
            return redirect(url_for("admin_panel"))

        denied = require_admin()
        if denied:
            return denied
        users = get_db().execute(
            "SELECT id, name, email, role, created_at FROM users ORDER BY id"
        ).fetchall()
        modules_data = [build_module(row) for row in module_rows()]
        question_rows = get_db().execute(
            """
            SELECT questions.*, modules.title AS module_title
            FROM questions JOIN modules ON modules.id = questions.module_id
            ORDER BY modules.title, questions.id
            """
        ).fetchall()
        questions = []
        for row in question_rows:
            question = dict(row)
            question["options"] = json.loads(question["options"])
            questions.append(question)
        tips_data = get_db().execute("SELECT * FROM tips ORDER BY category, id").fetchall()
        return render_template(
            "admin_panel.html",
            users=users,
            modules=modules_data,
            questions=questions,
            tips=tips_data,
        )

    @app.route("/logout", methods=["POST"])
    def logout():
        require_csrf()
        session.clear()
        return redirect(url_for("index"))

    initialize_database(DATABASE)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
