from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ==========================================
# USER MODEL
# ==========================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


# ==========================================
# URL SCAN MODEL
# ==========================================

class URLScan(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    url = db.Column(
        db.String(500),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    verdict = db.Column(
        db.String(50),
        nullable=False
    )

    findings = db.Column(
        db.Text
    )
    safe_browsing_checked = db.Column(
        db.Boolean,
        default=False
    )

    safe_browsing_safe = db.Column(
        db.Boolean,
        nullable=True
    )

    safe_browsing_threats = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )