from datetime import datetime
from typing import Optional
import os
import secrets
from uuid import uuid4
from pathlib import Path

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session

from .db import SessionLocal, engine
from .models import Base, Report, Attachment

app = FastAPI(title="Scam Report Hub")

security = HTTPBasic()

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_USER or not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_USER and ADMIN_PASSWORD must be set in the environment.")

Base.metadata.create_all(bind=engine)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


def get_db() -> Session:
    return SessionLocal()


@app.get("/", response_class=HTMLResponse)
def search_page(request: Request, q: Optional[str] = None, report_type: Optional[str] = None):
    with get_db() as db:
        stmt = (
            select(Report)
            .where(Report.deleted.is_(False), Report.is_flagged.is_(False))
            .order_by(Report.created_on.desc())
            .limit(200)
        )

        if report_type and report_type != "all":
            stmt = stmt.where(Report.report_type == report_type)

        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                or_(
                    Report.message_content.ilike(like),
                    Report.source_from.ilike(like),
                    Report.subject.ilike(like),
                )
            )

        reports = db.execute(stmt).scalars().all()
        report_ids = [r.id for r in reports]
        attachments_map = {}
        if report_ids:
            att_stmt = select(Attachment).where(
                Attachment.report_id.in_(report_ids),
                Attachment.deleted.is_(False),
            )
            attachments = db.execute(att_stmt).scalars().all()
            for att in attachments:
                attachments_map.setdefault(att.report_id, []).append(att)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "reports": reports,
                "attachments_map": attachments_map,
                "q": q or "",
                "report_type": report_type or "all",
            },
        )


@app.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request):
    return templates.TemplateResponse("submit.html", {"request": request})


@app.post("/submit")
def submit_report(
    report_type: str = Form(...),
    source_from: str = Form(""),
    subject: str = Form(""),
    message_content: str = Form(...),
    received_at: str = Form(""),
    reporter_name: str = Form(""),
    reporter_contact: str = Form(""),
    attachment: UploadFile | None = File(None),
):
    with get_db() as db:
        parsed_received_at = None
        if received_at:
            try:
                parsed_received_at = datetime.fromisoformat(received_at)
            except ValueError:
                parsed_received_at = None

        report = Report(
            report_type=report_type,
            source_from=source_from or None,
            subject=subject or None,
            message_content=message_content,
            received_at=parsed_received_at,
            reporter_name=reporter_name or None,
            reporter_contact=reporter_contact or None,
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        if attachment and attachment.filename:
            original_name = attachment.filename
            suffix = Path(original_name).suffix
            safe_name = f"{uuid4().hex}{suffix}"
            dest_path = UPLOAD_DIR / safe_name
            with dest_path.open("wb") as f:
                f.write(attachment.file.read())

            db.add(
                Attachment(
                    report_id=report.id,
                    original_name=original_name,
                    storage_path=str(dest_path),
                    mime_type=attachment.content_type,
                    size_bytes=dest_path.stat().st_size,
                )
            )
            db.commit()

        return RedirectResponse(url="/", status_code=303)


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    user_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    pass_ok = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    admin_user: str = Depends(require_admin),
    status: str = "all",
    show_deleted: int = 0,
    q: str = "",
    page: int = 1,
):
    with get_db() as db:
        page_size = 25
        page = max(page, 1)

        total_all = db.execute(select(func.count()).select_from(Report)).scalar_one()
        total_flagged = db.execute(
            select(func.count()).select_from(Report).where(Report.is_flagged.is_(True))
        ).scalar_one()
        total_deleted = db.execute(
            select(func.count()).select_from(Report).where(Report.deleted.is_(True))
        ).scalar_one()

        filters = []
        if not show_deleted:
            filters.append(Report.deleted.is_(False))
        if status == "flagged":
            filters.append(Report.is_flagged.is_(True))
        elif status == "unflagged":
            filters.append(Report.is_flagged.is_(False))
        if q:
            like = f"%{q}%"
            filters.append(
                or_(
                    Report.message_content.ilike(like),
                    Report.source_from.ilike(like),
                    Report.subject.ilike(like),
                )
            )

        count_stmt = select(func.count()).select_from(Report)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = db.execute(count_stmt).scalar_one()

        stmt = select(Report)
        if filters:
            stmt = stmt.where(*filters)
        stmt = stmt.order_by(Report.created_on.desc()).limit(page_size).offset((page - 1) * page_size)

        reports = db.execute(stmt).scalars().all()
        total_pages = max((total + page_size - 1) // page_size, 1)
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "reports": reports,
                "admin_user": admin_user,
                "status": status,
                "show_deleted": show_deleted,
                "q": q,
                "page": page,
                "total_pages": total_pages,
                "total": total,
                "total_all": total_all,
                "total_flagged": total_flagged,
                "total_deleted": total_deleted,
            },
        )


@app.post("/admin/action")
def admin_action(
    report_id: int = Form(...),
    action: str = Form(...),
    reason: str = Form(""),
    admin_user: str = Depends(require_admin),
):
    with get_db() as db:
        report = db.get(Report, report_id)
        if not report or report.deleted:
            return RedirectResponse(url="/admin", status_code=303)

        now = datetime.utcnow()
        if action == "flag":
            report.is_flagged = True
            report.flag_reason = reason or "flagged by admin"
            report.flagged_on = now
            report.flagged_by = admin_user
        elif action == "unflag":
            report.is_flagged = False
            report.flag_reason = None
            report.flagged_on = None
            report.flagged_by = None
        elif action == "delete":
            report.deleted = True
            report.deleted_on = now

        db.commit()
        return RedirectResponse(url="/admin", status_code=303)


@app.get("/attachments/{attachment_id}")
def download_attachment(attachment_id: int):
    with get_db() as db:
        att = db.get(Attachment, attachment_id)
        if not att or att.deleted:
            return RedirectResponse(url="/", status_code=303)

        report = db.get(Report, att.report_id)
        if not report or report.deleted or report.is_flagged:
            return RedirectResponse(url="/", status_code=303)

        return FileResponse(
            path=att.storage_path,
            filename=att.original_name,
            media_type=att.mime_type or "application/octet-stream",
        )
