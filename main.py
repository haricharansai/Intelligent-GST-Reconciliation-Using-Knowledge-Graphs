from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Header
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
import hashlib
import json
import csv
from io import StringIO
from jose import JWTError, jwt
from graph import GraphManager

# =============================================================================
# CONFIG
# =============================================================================
DATABASE_URL = "sqlite:///./gst_reconciliation.db"
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

# =============================================================================
# DATABASE SETUP
# =============================================================================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =============================================================================
# MODELS
# =============================================================================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String)
    gstin = Column(String, nullable=True)
    pan = Column(String, nullable=True)
    legal_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    settings = relationship("UserSetting", back_populates="user", cascade="all, delete-orphan")
    uploads = relationship("UploadedFile", back_populates="user", cascade="all, delete-orphan")


class UserSetting(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    tolerance = Column(Float, default=10.0)
    match_mode = Column(String, default="standard")
    date_window = Column(Integer, default=7)
    dup_rule = Column(String, default="strict")
    high_threshold = Column(Float, default=70.0)
    med_threshold = Column(Float, default=40.0)
    model = Column(String, default="rules")
    risk_boost = Column(String, default="low")
    email_alerts = Column(Boolean, default=True)
    auto_reports = Column(Boolean, default=True)
    audit_trail = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="settings")


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String)
    file_type = Column(String)  # gstr1, gstr3b, invoice, etc.
    file_path = Column(String)
    parsed_data = Column(JSON, nullable=True)
    validation_status = Column(String, default="pending")  # pending, valid, warning, invalid
    validation_errors = Column(JSON, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="uploads")


class ReconciliationResult(Base):
    __tablename__ = "reconciliation_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    gstr1_id = Column(Integer, ForeignKey("uploaded_files.id"))
    gstr3b_id = Column(Integer, ForeignKey("uploaded_files.id"))
    mismatches = Column(JSON, nullable=True)
    risk_items = Column(JSON, nullable=True)
    overall_status = Column(String)  # green, yellow, red, error
    created_at = Column(DateTime, default=datetime.utcnow)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    reset_code = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)


Base.metadata.create_all(bind=engine)

# =============================================================================
# PYDANTIC MODELS
# =============================================================================
class LoginRequest(BaseModel):
    userid: str
    password: str
    role: Optional[str] = None  # not trusted; token will use DB role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    role: str


class SettingsUpdate(BaseModel):
    tolerance: Optional[float] = None
    match_mode: Optional[str] = None
    date_window: Optional[int] = None
    dup_rule: Optional[str] = None
    high_threshold: Optional[float] = None
    med_threshold: Optional[float] = None
    model: Optional[str] = None
    risk_boost: Optional[str] = None
    email_alerts: Optional[bool] = None
    auto_reports: Optional[bool] = None
    audit_trail: Optional[bool] = None


class ReconcileRequest(BaseModel):
    gstr1_id: int
    gstr3b_id: int


# =============================================================================
# FASTAPI APP
# =============================================================================
app = FastAPI(title="GST Reconciliation Engine", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# DEPENDENCIES
# =============================================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(sub)
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# =============================================================================
# HELPERS
# =============================================================================
def hash_password(password: str) -> str:
    # Keep your sha256 for now (works). If you want stronger hashing, tell me and I'll upgrade.
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_access_token(user_id: int, role: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": str(user_id), "role": role, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def generate_reset_code() -> str:
    """Generate a 6-digit reset code."""
    import random
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def safe_filename(name: str) -> str:
    # Prevent ../../ attacks
    return os.path.basename(name).replace("\\", "_").replace("/", "_")


def parse_float(x: Any) -> float:
    try:
        if x is None:
            return 0.0
        if isinstance(x, (int, float)):
            return float(x)
        s = str(x).strip().replace(",", "")
        return float(s) if s else 0.0
    except Exception:
        return 0.0


def parse_gst_file(filename: str, content_bytes: bytes) -> Dict:
    """
    Parse CSV/JSON and extract:
      - row_count
      - columns
      - sample
      - totals (taxable_value, total_gst) if columns exist
    """
    try:
        lower = filename.lower()

        if lower.endswith(".csv"):
            content_str = content_bytes.decode("utf-8", errors="replace")
            reader = csv.DictReader(StringIO(content_str))
            rows = list(reader)
            if not rows:
                return {"status": "error", "message": "CSV file is empty"}

            columns = list(rows[0].keys())
            cols_lower = {c.lower(): c for c in columns}

            # These are common column names you might see
            gst_col_candidates = ["total_gst", "gst", "igst+cgst+sgst", "tax_amount", "tax"]
            taxable_candidates = ["taxable_value", "taxable", "taxableamount", "taxable amount"]

            def find_col(candidates):
                for cand in candidates:
                    for k in cols_lower:
                        if k.replace(" ", "_") == cand or k == cand:
                            return cols_lower[k]
                return None

            gst_col = find_col(gst_col_candidates)
            taxable_col = find_col(taxable_candidates)

            total_gst = 0.0
            total_taxable = 0.0
            for r in rows:
                if gst_col:
                    total_gst += parse_float(r.get(gst_col))
                if taxable_col:
                    total_taxable += parse_float(r.get(taxable_col))

            required_cols = {"gstin", "invoice_no", "invoice_date", "taxable_value"}
            available_cols = set(c.lower() for c in columns)
            missing = required_cols - available_cols

            status = "success" if not missing else "warning"
            msg = "" if not missing else f"Missing columns: {', '.join(sorted(missing))}. Will continue."

            return {
                "status": status,
                "message": msg,
                "row_count": len(rows),
                "columns": columns,
                "sample": rows[0],
                "totals": {
                    "taxable_value": round(total_taxable, 2),
                    "total_gst": round(total_gst, 2),
                },
            }

        if lower.endswith(".json"):
            data = json.loads(content_bytes.decode("utf-8", errors="replace"))
            if not isinstance(data, list):
                return {"status": "error", "message": "JSON must be an array of objects"}
            if not data:
                return {"status": "error", "message": "JSON array is empty"}
            if not isinstance(data[0], dict):
                return {"status": "error", "message": "JSON array must contain objects"}

            columns = list(data[0].keys())
            total_gst = 0.0
            total_taxable = 0.0
            for r in data:
                if isinstance(r, dict):
                    total_gst += parse_float(r.get("total_gst") or r.get("gst") or r.get("tax"))
                    total_taxable += parse_float(r.get("taxable_value") or r.get("taxable"))

            return {
                "status": "success",
                "row_count": len(data),
                "columns": columns,
                "sample": data[0],
                "totals": {
                    "taxable_value": round(total_taxable, 2),
                    "total_gst": round(total_gst, 2),
                },
            }

        if lower.endswith((".xlsx", ".xls")):
            return {
                "status": "warning",
                "message": "Excel files detected. Install openpyxl for full parsing: pip install openpyxl",
                "row_count": "unknown",
                "columns": [],
            }

        return {"status": "error", "message": "Unsupported file format. Use CSV, JSON, or Excel."}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def reconcile_gstr1_gstr3b(gstr1_data: Dict, gstr3b_data: Dict, tolerance: float) -> Dict:
    """
    Compare total_gst from parsed totals.
    Your parsed_data is like: { ..., "totals": {"total_gst": 123.45} }
    """
    try:
        g1_total = parse_float((gstr1_data.get("totals") or {}).get("total_gst"))
        g3_total = parse_float((gstr3b_data.get("totals") or {}).get("total_gst"))

        diff = abs(g1_total - g3_total)
        pct_diff = (diff / g1_total * 100) if g1_total > 0 else 0.0

        if pct_diff <= tolerance:
            status = "green"
        elif pct_diff <= tolerance * 2:
            status = "yellow"
        else:
            status = "red"

        return {
            "gstr1_total_gst": round(g1_total, 2),
            "gstr3b_total_gst": round(g3_total, 2),
            "difference": round(diff, 2),
            "pct_difference": round(pct_diff, 2),
            "tolerance": tolerance,
            "status": status,
            "message": f"Difference of {round(pct_diff, 2)}% detected",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# =============================================================================
# ROUTES - STATIC
# =============================================================================
@app.get("/")
def root():
    return RedirectResponse(url="/Main.html")


@app.get("/{page_name}.html")
def serve_page(page_name: str):
    path = f"{page_name}.html"
    if os.path.isfile(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Page not found")


@app.get("/{full_path:path}")
def serve_any(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    if os.path.isfile(full_path):
        return FileResponse(full_path)
    raise HTTPException(status_code=404)


# =============================================================================
# ROUTES - AUTH
# =============================================================================
@app.post("/api/register")
def register(user_data: dict, db: Session = Depends(get_db)):
    login = user_data.get("login")
    password = user_data.get("password")
    role = user_data.get("role")

    if not login or not password or not role:
        raise HTTPException(status_code=400, detail="Missing required fields")

    existing = db.query(User).filter(User.login == login).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    user = User(
        login=login,
        password_hash=hash_password(password),
        role=role,
        gstin=user_data.get("gstin"),
        pan=user_data.get("pan"),
        legal_name=user_data.get("legalBusinessName"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    settings = UserSetting(user_id=user.id)
    db.add(settings)
    db.commit()

    return {"status": "success", "user": login, "user_id": user.id}


@app.post("/api/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.login == req.userid).first()
    if not user or user.password_hash != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.id, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "role": user.role,
    }


@app.post("/api/forgot-password")
def forgot_password(data: dict, db: Session = Depends(get_db)):
    """Generate and send password reset code."""
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    user = db.query(User).filter(User.login == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate reset code
    reset_code = generate_reset_code()
    
    # Delete old reset tokens for this user
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete()
    db.commit()
    
    # Create new reset token (valid for 15 minutes)
    expires_at = datetime.utcnow() + timedelta(minutes=15)
    token = PasswordResetToken(user_id=user.id, reset_code=reset_code, expires_at=expires_at)
    db.add(token)
    db.commit()
    
    # In production: send email with reset code
    # For demo: print to console (replace with email service)
    print(f"🔑 Reset code for {email}: {reset_code}")
    
    return {
        "status": "success",
        "message": f"Reset code sent to {email}",
        "code": reset_code  # FOR TESTING ONLY - remove in production
    }


@app.post("/api/reset-password")
def reset_password(data: dict, db: Session = Depends(get_db)):
    """Validate reset code and update password."""
    email = data.get("email", "").strip()
    code = data.get("code", "").strip()
    password = data.get("password", "")
    
    if not email or not code or not password:
        raise HTTPException(status_code=400, detail="Missing required fields")
    
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Find user
    user = db.query(User).filter(User.login == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Find and validate reset token
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.reset_code == code
    ).first()
    
    if not reset_token:
        raise HTTPException(status_code=401, detail="Invalid reset code")
    
    if datetime.utcnow() > reset_token.expires_at:
        db.delete(reset_token)
        db.commit()
        raise HTTPException(status_code=401, detail="Reset code expired")
    
    # Update password
    user.password_hash = hash_password(password)
    db.add(user)
    
    # Delete used token
    db.delete(reset_token)
    db.commit()
    
    return {
        "status": "success",
        "message": "Password reset successful"
    }


# =============================================================================
# ROUTES - SETTINGS
# =============================================================================
@app.get("/api/settings")
def get_settings(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = db.query(UserSetting).filter(UserSetting.user_id == current_user.id).first()
    if not settings:
        settings = UserSetting(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return {
        "tolerance": settings.tolerance,
        "match_mode": settings.match_mode,
        "date_window": settings.date_window,
        "dup_rule": settings.dup_rule,
        "high_threshold": settings.high_threshold,
        "med_threshold": settings.med_threshold,
        "model": settings.model,
        "risk_boost": settings.risk_boost,
        "email_alerts": settings.email_alerts,
        "auto_reports": settings.auto_reports,
        "audit_trail": settings.audit_trail,
    }


@app.post("/api/settings")
def update_settings(
    settings_data: SettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings = db.query(UserSetting).filter(UserSetting.user_id == current_user.id).first()
    if not settings:
        settings = UserSetting(user_id=current_user.id)
        db.add(settings)

    update_data = settings_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(settings, key, value)

    db.commit()
    return {"status": "success", "message": "Settings updated"}


# =============================================================================
# ROUTES - UPLOAD
# =============================================================================
@app.post("/api/upload")
async def upload_files(
    gstr1: Optional[UploadFile] = File(None),
    gstr3b: Optional[UploadFile] = File(None),
    invoice: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    uploaded_files = {}

    for file_obj, file_type in [(gstr1, "gstr1"), (gstr3b, "gstr3b"), (invoice, "invoice")]:
        if file_obj is None:
            continue

        try:
            content = await file_obj.read()

            # Save file
            file_dir = os.path.join("uploads", str(current_user.id))
            os.makedirs(file_dir, exist_ok=True)

            safe_name = safe_filename(file_obj.filename)
            file_path = os.path.join(file_dir, safe_name)
            with open(file_path, "wb") as f:
                f.write(content)

            parse_result = parse_gst_file(safe_name, content)

            status = parse_result.get("status")
            validation_status = "valid" if status == "success" else ("warning" if status == "warning" else "invalid")
            validation_errors = None if status == "success" else [parse_result.get("message", "Unknown issue")]

            db_file = UploadedFile(
                user_id=current_user.id,
                filename=safe_name,
                file_type=file_type,
                file_path=file_path,
                parsed_data=parse_result,
                validation_status=validation_status,
                validation_errors=validation_errors,
            )
            db.add(db_file)
            db.commit()
            db.refresh(db_file)

            uploaded_files[file_type] = {
                "id": db_file.id,
                "filename": safe_name,
                "status": status,
                "message": parse_result.get("message", ""),
                "row_count": parse_result.get("row_count"),
                "totals": parse_result.get("totals"),
            }

        except Exception as e:
            uploaded_files[file_type] = {"filename": file_obj.filename, "status": "error", "message": str(e)}

    return {"status": "received", "files": uploaded_files}


@app.get("/api/uploads")
def list_uploads(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    files = db.query(UploadedFile).filter(UploadedFile.user_id == current_user.id).all()
    return {
        "uploads": [
            {
                "id": f.id,
                "filename": f.filename,
                "file_type": f.file_type,
                "validation_status": f.validation_status,
                "validation_errors": f.validation_errors,
                "uploaded_at": f.uploaded_at.isoformat(),
                "parsed_data": f.parsed_data,
            }
            for f in files
        ]
    }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

# =============================================================================
# ROUTES - RECONCILIATION
# =============================================================================
@app.post("/api/reconcile")
def run_reconciliation(
    body: ReconcileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings = db.query(UserSetting).filter(UserSetting.user_id == current_user.id).first()
    tolerance = settings.tolerance if settings else 10.0

    gstr1_file = (
        db.query(UploadedFile)
        .filter(UploadedFile.id == body.gstr1_id, UploadedFile.user_id == current_user.id)
        .first()
    )
    gstr3b_file = (
        db.query(UploadedFile)
        .filter(UploadedFile.id == body.gstr3b_id, UploadedFile.user_id == current_user.id)
        .first()
    )

    if not gstr1_file or not gstr3b_file:
        raise HTTPException(status_code=404, detail="Files not found")

    gstr1_data = gstr1_file.parsed_data or {}
    gstr3b_data = gstr3b_file.parsed_data or {}

    result = reconcile_gstr1_gstr3b(gstr1_data, gstr3b_data, tolerance)

    recon = ReconciliationResult(
        user_id=current_user.id,
        gstr1_id=gstr1_file.id,
        gstr3b_id=gstr3b_file.id,
        mismatches=result,
        overall_status=result.get("status", "error"),
    )
    db.add(recon)
    db.commit()

    return {"status": "success", "reconciliation": result}


# =============================================================================
# ROUTES - DASHBOARD
# =============================================================================
@app.get("/api/dashboard")
def get_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file_count = db.query(UploadedFile).filter(UploadedFile.user_id == current_user.id).count()
    recent_files = (
        db.query(UploadedFile)
        .filter(UploadedFile.user_id == current_user.id)
        .order_by(UploadedFile.uploaded_at.desc())
        .limit(5)
        .all()
    )

    recon_count = db.query(ReconciliationResult).filter(ReconciliationResult.user_id == current_user.id).count()
    recent_recon = (
        db.query(ReconciliationResult)
        .filter(ReconciliationResult.user_id == current_user.id)
        .order_by(ReconciliationResult.created_at.desc())
        .limit(3)
        .all()
    )

    return {
        "user_id": current_user.id,
        "role": current_user.role,
        "total_uploads": file_count,
        "recent_uploads": [
            {"filename": f.filename, "type": f.file_type, "status": f.validation_status, "date": f.uploaded_at.isoformat()}
            for f in recent_files
        ],
        "total_reconciliations": recon_count,
        "recent_reconciliations": [{"status": r.overall_status, "date": r.created_at.isoformat()} for r in recent_recon],
    }


# =============================================================================
# ROUTES - GRAPH / KNOWLEDGE GRAPH
# =============================================================================


@app.post("/api/graph/build")
def build_graph(payload: dict = {}, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Build the GST knowledge graph for the current user.

    Optional payload: { "upload_ids": [1,2,3] }
    """
    upload_ids = payload.get("upload_ids") if isinstance(payload, dict) else None
    gm = GraphManager(db, current_user.id)
    res = gm.build_graph(upload_ids=upload_ids)
    return {"status": "success", "result": res}


@app.get("/api/graph/mismatches")
def graph_mismatches(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Detect mismatches using the built graph and user tolerance settings."""
    gm = GraphManager(db, current_user.id)
    loaded = gm.load_graph()
    if not loaded:
        # Try building on the fly
        gm.build_graph()

    settings = db.query(UserSetting).filter(UserSetting.user_id == current_user.id).first()
    tolerance = settings.tolerance if settings else 10.0
    res = gm.detect_mismatches(tolerance_pct=float(tolerance))
    return {"status": "success", "result": res}


@app.get("/api/graph/stats")
def graph_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    gm = GraphManager(db, current_user.id)
    if not gm.load_graph():
        gm.build_graph()
    return {"status": "success", "nodes": gm.G.number_of_nodes(), "edges": gm.G.number_of_edges()}


print("✅ Database initialized, all endpoints ready")