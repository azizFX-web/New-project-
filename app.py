"""
InvoicePilot — Invoicing & billing tool for freelancers
============================================================
Butunlay mustaqil loyiha (kafe botiga bog'liq emas).

O'RNATISH:
  pip install -r requirements.txt
  uvicorn app:app --host 0.0.0.0 --port 8080

ENV VARIABLES (.env yoki Railway Variables):
  SECRET_KEY      -> sessiya tokenlarini xeshlash uchun (o'zingiz o'ylab toping)
  SMTP_HOST       -> email yuborish uchun SMTP server (masalan smtp.gmail.com)
  SMTP_PORT       -> odatda 587
  SMTP_USER       -> SMTP login (email manzil)
  SMTP_PASS       -> SMTP parol / app password
  FROM_EMAIL      -> "InvoicePilot <you@example.com>"
  PUBLIC_URL      -> https://sizning-domen.railway.app (public invoice link uchun)

Agar SMTP sozlanmagan bo'lsa, eslatma email'lari jim tarzda o'tkazib yuboriladi (xato bermaydi).
"""

import hashlib
import json
import logging
import os
import secrets
import smtplib
import sqlite3
import uuid
from datetime import datetime, timedelta, date
from email.mime.text import MIMEText

from fastapi import FastAPI, Request, Response, HTTPException, Cookie, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from io import BytesIO

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("invoicepilot")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "InvoicePilot <noreply@invoicepilot.app>")
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8080")

DB_PATH = "invoicepilot.db"

app = FastAPI(title="InvoicePilot")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DB HELPERS
# ============================================================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            business_name TEXT,
            business_address TEXT,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            company TEXT,
            address TEXT,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            invoice_number TEXT NOT NULL,
            currency TEXT DEFAULT 'USD',
            issue_date TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'draft',
            notes TEXT,
            share_token TEXT UNIQUE,
            created_at TEXT,
            paid_at TEXT,
            last_reminder_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            quantity REAL DEFAULT 1,
            unit_price REAL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# ============================================================
# AUTH HELPERS
# ============================================================
def hash_password(password: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$")
    except ValueError:
        return False
    return hash_password(password, salt) == stored


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn = db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
        (token, user_id, (datetime.now() + timedelta(days=30)).isoformat()),
    )
    conn.commit()
    conn.close()
    return token


def get_current_user(session: str = Cookie(default=None)):
    if not session:
        raise HTTPException(status_code=401, detail="Login required")
    conn = db()
    row = conn.execute(
        "SELECT s.user_id, s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
        (session,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Login required")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        raise HTTPException(status_code=401, detail="Session expired")
    return dict(row)


def invoice_total(conn, invoice_id):
    items = conn.execute("SELECT * FROM invoice_items WHERE invoice_id=?", (invoice_id,)).fetchall()
    return round(sum(i["quantity"] * i["unit_price"] for i in items), 2)


# ============================================================
# EMAIL
# ============================================================
def send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST or not to_email:
        log.info(f"[EMAIL SKIPPED — SMTP sozlanmagan] to={to_email} subject={subject}")
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [to_email], msg.as_string())
        log.info(f"Email yuborildi: {to_email} — {subject}")
    except Exception as e:
        log.error(f"Email yuborishda xatolik ({to_email}): {e}")


# ============================================================
# AUTH ENDPOINTS
# ============================================================
@app.post("/api/register")
async def register(request: Request, response: Response):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    name = str(data.get("name", "")).strip()
    business_name = str(data.get("business_name", "")).strip()

    if not email or not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Email va kamida 6 belgili parol kerak")

    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, name, business_name, created_at) VALUES (?,?,?,?,?)",
            (email, hash_password(password), name, business_name, datetime.now().isoformat()),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Bu email allaqachon ro'yxatdan o'tgan")
    conn.close()

    token = create_session(user_id)
    response.set_cookie("session", token, httponly=True, max_age=60 * 60 * 24 * 30, samesite="lax")
    return {"ok": True}


@app.post("/api/login")
async def login(request: Request, response: Response):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    conn = db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email yoki parol xato")

    token = create_session(row["id"])
    response.set_cookie("session", token, httponly=True, max_age=60 * 60 * 24 * 30, samesite="lax")
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response, session: str = Cookie(default=None)):
    if session:
        conn = db()
        conn.execute("DELETE FROM sessions WHERE token=?", (session,))
        conn.commit()
        conn.close()
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/api/me")
async def me(user=Depends(get_current_user)):
    return {
        "email": user["email"], "name": user["name"],
        "business_name": user["business_name"], "business_address": user["business_address"],
    }


@app.post("/api/me")
async def update_me(request: Request, user=Depends(get_current_user)):
    data = await request.json()
    conn = db()
    conn.execute(
        "UPDATE users SET name=?, business_name=?, business_address=? WHERE id=?",
        (data.get("name", ""), data.get("business_name", ""), data.get("business_address", ""), user["id"]),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


# ============================================================
# CLIENTS
# ============================================================
@app.get("/api/clients")
async def list_clients(user=Depends(get_current_user)):
    conn = db()
    rows = conn.execute("SELECT * FROM clients WHERE user_id=? ORDER BY name", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/clients")
async def add_client(request: Request, user=Depends(get_current_user)):
    data = await request.json()
    name = str(data.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Mijoz ismi kerak")
    conn = db()
    conn.execute(
        "INSERT INTO clients (user_id, name, email, company, address, created_at) VALUES (?,?,?,?,?,?)",
        (user["id"], name, data.get("email", ""), data.get("company", ""), data.get("address", ""), datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: int, user=Depends(get_current_user)):
    conn = db()
    conn.execute("DELETE FROM clients WHERE id=? AND user_id=?", (client_id, user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ============================================================
# INVOICES
# ============================================================
def next_invoice_number(conn, user_id):
    count = conn.execute("SELECT COUNT(*) c FROM invoices WHERE user_id=?", (user_id,)).fetchone()["c"]
    return f"INV-{datetime.now().year}-{count + 1:04d}"


@app.get("/api/invoices")
async def list_invoices(user=Depends(get_current_user)):
    conn = db()
    rows = conn.execute(
        """SELECT i.*, c.name as client_name, c.email as client_email
           FROM invoices i JOIN clients c ON c.id = i.client_id
           WHERE i.user_id=? ORDER BY i.id DESC""",
        (user["id"],),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["total"] = invoice_total(conn, r["id"])
        # avtomatik "overdue" belgilash (agar muddati o'tgan bo'lsa)
        if d["status"] == "sent" and d["due_date"] and d["due_date"] < date.today().isoformat():
            d["status"] = "overdue"
        result.append(d)
    conn.close()
    return result


@app.post("/api/invoices")
async def create_invoice(request: Request, user=Depends(get_current_user)):
    data = await request.json()
    client_id = data.get("client_id")
    items = data.get("items", [])
    if not client_id or not items:
        raise HTTPException(status_code=400, detail="Mijoz va kamida bitta qator kerak")

    conn = db()
    client = conn.execute("SELECT id FROM clients WHERE id=? AND user_id=?", (client_id, user["id"])).fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=400, detail="Mijoz topilmadi")

    number = next_invoice_number(conn, user["id"])
    share_token = secrets.token_urlsafe(16)
    cur = conn.execute(
        """INSERT INTO invoices (user_id, client_id, invoice_number, currency, issue_date, due_date,
           status, notes, share_token, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            user["id"], client_id, number, data.get("currency", "USD"),
            data.get("issue_date", date.today().isoformat()), data.get("due_date", ""),
            "draft", data.get("notes", ""), share_token, datetime.now().isoformat(),
        ),
    )
    invoice_id = cur.lastrowid
    for it in items:
        conn.execute(
            "INSERT INTO invoice_items (invoice_id, description, quantity, unit_price) VALUES (?,?,?,?)",
            (invoice_id, it.get("description", ""), float(it.get("quantity", 1)), float(it.get("unit_price", 0))),
        )
    conn.commit()
    conn.close()
    return {"ok": True, "invoice_id": invoice_id, "invoice_number": number}


@app.get("/api/invoices/{invoice_id}")
async def get_invoice(invoice_id: int, user=Depends(get_current_user)):
    conn = db()
    inv = conn.execute(
        """SELECT i.*, c.name as client_name, c.email as client_email, c.company as client_company, c.address as client_address
           FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=? AND i.user_id=?""",
        (invoice_id, user["id"]),
    ).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Topilmadi")
    items = conn.execute("SELECT * FROM invoice_items WHERE invoice_id=?", (invoice_id,)).fetchall()
    d = dict(inv)
    d["items"] = [dict(i) for i in items]
    d["total"] = invoice_total(conn, invoice_id)
    conn.close()
    return d


@app.patch("/api/invoices/{invoice_id}")
async def update_invoice_status(invoice_id: int, request: Request, user=Depends(get_current_user)):
    data = await request.json()
    status = data.get("status")
    if status not in ("draft", "sent", "paid", "overdue"):
        raise HTTPException(status_code=400, detail="Noto'g'ri status")

    conn = db()
    inv = conn.execute(
        "SELECT i.*, c.email as client_email, c.name as client_name FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=? AND i.user_id=?",
        (invoice_id, user["id"]),
    ).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Topilmadi")

    paid_at = datetime.now().isoformat() if status == "paid" else inv["paid_at"]
    conn.execute("UPDATE invoices SET status=?, paid_at=? WHERE id=?", (status, paid_at, invoice_id))
    conn.commit()
    conn.close()

    if status == "sent" and inv["client_email"]:
        link = f"{PUBLIC_URL}/invoice/{inv['share_token']}"
        send_email(
            inv["client_email"], f"Invoice {inv['invoice_number']}",
            f"Hi {inv['client_name']},\n\nYou have a new invoice ({inv['invoice_number']}).\nView & download: {link}\n\nThank you!",
        )
    return {"ok": True}


@app.delete("/api/invoices/{invoice_id}")
async def delete_invoice(invoice_id: int, user=Depends(get_current_user)):
    conn = db()
    conn.execute("DELETE FROM invoices WHERE id=? AND user_id=?", (invoice_id, user["id"]))
    conn.execute("DELETE FROM invoice_items WHERE invoice_id=?", (invoice_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/invoices/{invoice_id}/remind")
async def send_reminder(invoice_id: int, user=Depends(get_current_user)):
    conn = db()
    inv = conn.execute(
        "SELECT i.*, c.email as client_email, c.name as client_name FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.id=? AND i.user_id=?",
        (invoice_id, user["id"]),
    ).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Topilmadi")
    total = invoice_total(conn, invoice_id)
    conn.execute("UPDATE invoices SET last_reminder_at=? WHERE id=?", (datetime.now().isoformat(), invoice_id))
    conn.commit()
    conn.close()

    if inv["client_email"]:
        link = f"{PUBLIC_URL}/invoice/{inv['share_token']}"
        send_email(
            inv["client_email"], f"Reminder: Invoice {inv['invoice_number']} is due",
            f"Hi {inv['client_name']},\n\nThis is a friendly reminder that invoice {inv['invoice_number']} "
            f"({inv['currency']} {total}) is due on {inv['due_date']}.\nView & pay: {link}\n\nThank you!",
        )
    return {"ok": True}


# ============================================================
# PDF GENERATION
# ============================================================
def build_invoice_pdf(invoice: dict, user: dict) -> BytesIO:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    ink = colors.HexColor("#0F172A")
    accent = colors.HexColor("#3B82F6")
    muted = colors.HexColor("#64748B")

    # Header
    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(20 * mm, h - 25 * mm, user.get("business_name") or user.get("name") or "InvoicePilot")
    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 14)
    c.drawRightString(w - 20 * mm, h - 25 * mm, "INVOICE")

    c.setFillColor(muted)
    c.setFont("Helvetica", 9)
    if user.get("business_address"):
        c.drawString(20 * mm, h - 31 * mm, user["business_address"])

    c.setFont("Helvetica", 10)
    c.drawRightString(w - 20 * mm, h - 32 * mm, f"# {invoice['invoice_number']}")
    c.drawRightString(w - 20 * mm, h - 37 * mm, f"Issue date: {invoice['issue_date']}")
    c.drawRightString(w - 20 * mm, h - 42 * mm, f"Due date: {invoice['due_date'] or '-'}")

    # Bill to
    y = h - 55 * mm
    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(20 * mm, y, "BILL TO")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y - 6 * mm, invoice["client_name"])
    if invoice.get("client_company"):
        c.drawString(20 * mm, y - 11 * mm, invoice["client_company"])
    if invoice.get("client_address"):
        c.drawString(20 * mm, y - 16 * mm, invoice["client_address"])

    # Items table
    y = h - 85 * mm
    c.setFillColor(colors.HexColor("#F1F5F9"))
    c.rect(20 * mm, y, w - 40 * mm, 8 * mm, fill=True, stroke=False)
    c.setFillColor(ink)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(22 * mm, y + 2.5 * mm, "DESCRIPTION")
    c.drawRightString(w - 90 * mm, y + 2.5 * mm, "QTY")
    c.drawRightString(w - 60 * mm, y + 2.5 * mm, "UNIT PRICE")
    c.drawRightString(w - 22 * mm, y + 2.5 * mm, "AMOUNT")

    y -= 10 * mm
    c.setFont("Helvetica", 9.5)
    for item in invoice["items"]:
        amount = item["quantity"] * item["unit_price"]
        c.drawString(22 * mm, y, item["description"][:60])
        c.drawRightString(w - 90 * mm, y, f"{item['quantity']:g}")
        c.drawRightString(w - 60 * mm, y, f"{item['unit_price']:,.2f}")
        c.drawRightString(w - 22 * mm, y, f"{amount:,.2f}")
        y -= 7 * mm
        if y < 40 * mm:
            c.showPage()
            y = h - 30 * mm

    # Total
    y -= 4 * mm
    c.setStrokeColor(colors.HexColor("#E2E8F0"))
    c.line(w - 90 * mm, y, w - 22 * mm, y)
    y -= 8 * mm
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(accent)
    c.drawRightString(w - 22 * mm, y, f"Total: {invoice['currency']} {invoice['total']:,.2f}")

    # Notes
    if invoice.get("notes"):
        y -= 15 * mm
        c.setFillColor(muted)
        c.setFont("Helvetica", 9)
        c.drawString(20 * mm, y, "Notes:")
        c.drawString(20 * mm, y - 5 * mm, invoice["notes"][:100])

    c.setFillColor(muted)
    c.setFont("Helvetica", 8)
    c.drawCentredString(w / 2, 12 * mm, "Generated with InvoicePilot")

    c.save()
    buf.seek(0)
    return buf


@app.get("/api/invoices/{invoice_id}/pdf")
async def download_pdf(invoice_id: int, user=Depends(get_current_user)):
    invoice = await get_invoice(invoice_id, user)
    pdf = build_invoice_pdf(invoice, user)
    return StreamingResponse(
        pdf, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={invoice['invoice_number']}.pdf"},
    )


# ============================================================
# PUBLIC SHARE LINK — mijoz login qilmasdan ko'radi
# ============================================================
@app.get("/api/public/invoice/{token}")
async def public_invoice(token: str):
    conn = db()
    inv = conn.execute(
        """SELECT i.*, c.name as client_name, c.email as client_email, c.company as client_company, c.address as client_address,
                  u.business_name, u.business_address, u.name as freelancer_name
           FROM invoices i JOIN clients c ON c.id=i.client_id JOIN users u ON u.id=i.user_id
           WHERE i.share_token=?""",
        (token,),
    ).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Invoice not found")
    items = conn.execute("SELECT * FROM invoice_items WHERE invoice_id=?", (inv["id"],)).fetchall()
    d = dict(inv)
    d["items"] = [dict(i) for i in items]
    d["total"] = invoice_total(conn, inv["id"])
    conn.close()
    return d


@app.get("/api/public/invoice/{token}/pdf")
async def public_invoice_pdf(token: str):
    conn = db()
    inv = conn.execute(
        """SELECT i.*, c.name as client_name, c.email as client_email, c.company as client_company, c.address as client_address,
                  u.business_name, u.business_address, u.name as freelancer_name
           FROM invoices i JOIN clients c ON c.id=i.client_id JOIN users u ON u.id=i.user_id
           WHERE i.share_token=?""",
        (token,),
    ).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Invoice not found")
    items = conn.execute("SELECT * FROM invoice_items WHERE invoice_id=?", (inv["id"],)).fetchall()
    d = dict(inv)
    d["items"] = [dict(i) for i in items]
    d["total"] = invoice_total(conn, inv["id"])
    conn.close()
    user_like = {"business_name": inv["business_name"], "name": inv["freelancer_name"], "business_address": inv["business_address"]}
    pdf = build_invoice_pdf(d, user_like)
    return StreamingResponse(pdf, media_type="application/pdf")


# ============================================================
# DASHBOARD STATS
# ============================================================
@app.get("/api/stats")
async def stats(user=Depends(get_current_user)):
    conn = db()
    rows = conn.execute("SELECT * FROM invoices WHERE user_id=?", (user["id"],)).fetchall()
    outstanding, paid_this_month, overdue_count = 0, 0, 0
    this_month = date.today().strftime("%Y-%m")
    for r in rows:
        total = invoice_total(conn, r["id"])
        if r["status"] in ("sent", "overdue"):
            outstanding += total
        if r["status"] == "sent" and r["due_date"] and r["due_date"] < date.today().isoformat():
            overdue_count += 1
        if r["status"] == "paid" and r["paid_at"] and r["paid_at"].startswith(this_month):
            paid_this_month += total
    conn.close()
    return {
        "outstanding": round(outstanding, 2),
        "paid_this_month": round(paid_this_month, 2),
        "overdue_count": overdue_count,
        "total_invoices": len(rows),
    }


# ============================================================
# BACKGROUND: kunlik avtomatik eslatma (overdue invoyslar uchun)
# ============================================================
async def daily_reminder_check():
    import asyncio
    while True:
        try:
            conn = db()
            rows = conn.execute(
                """SELECT i.*, c.email as client_email, c.name as client_name
                   FROM invoices i JOIN clients c ON c.id=i.client_id
                   WHERE i.status='sent' AND i.due_date < ?""",
                (date.today().isoformat(),),
            ).fetchall()
            for inv in rows:
                last = inv["last_reminder_at"]
                if last and (datetime.now() - datetime.fromisoformat(last)).days < 3:
                    continue  # 3 kunda bir marta yuboramiz
                total = invoice_total(conn, inv["id"])
                if inv["client_email"]:
                    link = f"{PUBLIC_URL}/invoice/{inv['share_token']}"
                    send_email(
                        inv["client_email"], f"Overdue: Invoice {inv['invoice_number']}",
                        f"Hi {inv['client_name']},\n\nInvoice {inv['invoice_number']} ({inv['currency']} {total}) "
                        f"was due on {inv['due_date']} and is now overdue.\nView & pay: {link}\n\nThank you!",
                    )
                conn.execute("UPDATE invoices SET last_reminder_at=? WHERE id=?", (datetime.now().isoformat(), inv["id"]))
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"daily_reminder_check xatolik: {e}")
        await __import__("asyncio").sleep(60 * 60 * 12)  # har 12 soatda tekshiradi


@app.on_event("startup")
async def on_startup():
    init_db()
    import asyncio
    asyncio.create_task(daily_reminder_check())


# ============================================================
# STATIC PAGES
# ============================================================
@app.get("/")
async def home():
    return FileResponse("index.html")


@app.get("/invoice/{token}")
async def public_invoice_page(token: str):
    return FileResponse("public_invoice.html")
