# app.py
import os
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, MetaData, select, insert, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

import re
from urllib.parse import urlparse

# Timezone libs
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None
import pytz
from tzlocal import get_localzone_name

load_dotenv()

# -------------------------
# Config / DB
# -------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    st.stop()  # stops the app with no DB configured

engine = create_engine(DATABASE_URL, future=True)
metadata = MetaData()
metadata.reflect(bind=engine)

# table handles
reports = metadata.tables.get("reports")
report_links = metadata.tables.get("report_links")
attachments = metadata.tables.get("attachments")
report_audit = metadata.tables.get("report_audit")
posing_as = metadata.tables.get("posing_as")
users = metadata.tables.get("users")

# -------------------------
# Helpers
# -------------------------
def safe_rows(stmt):
    try:
        with engine.connect() as conn:
            res = conn.execute(stmt)
            return res.fetchall(), res.keys()
    except SQLAlchemyError as e:
        st.error(f"DB error: {e}")
        return [], []

def insert_and_return_id(table, payload):
    try:
        with engine.begin() as conn:
            res = conn.execute(insert(table).returning(table.c.id), payload)
            return res.scalar_one()
    except SQLAlchemyError as e:
        st.error(f"Insert error: {e}")
        return None

def insert_simple(table, payload):
    try:
        with engine.begin() as conn:
            conn.execute(insert(table), payload)
            return True
    except SQLAlchemyError as e:
        st.error(f"Insert error: {e}")
        return False

def convert_local_to_utc(naive_dt, tz_name):
    """Return timezone-aware UTC datetime from naive local datetime and tz_name."""
    if tz_name is None:
        return naive_dt.replace(tzinfo=pytz.utc)
    try:
        if ZoneInfo:
            local = naive_dt.replace(tzinfo=ZoneInfo(tz_name))
            return local.astimezone(ZoneInfo("UTC"))
        else:
            local_tz = pytz.timezone(tz_name)
            local = local_tz.localize(naive_dt)
            return local.astimezone(pytz.utc)
    except Exception:
        # fallback: assume naive_dt is already UTC
        return naive_dt.replace(tzinfo=pytz.utc)

def convert_utc_to_local(utc_dt, tz_name):
    """Return localized datetime for display. If tz invalid or missing, return utc_dt."""
    if utc_dt is None:
        return None
    try:
        if tz_name:
            if ZoneInfo:
                return utc_dt.astimezone(ZoneInfo(tz_name))
            else:
                return utc_dt.astimezone(pytz.timezone(tz_name))
    except Exception:
        return utc_dt

# -------------------------
# Page layout
# -------------------------
st.set_page_config(layout="wide", page_title="Scam Reports")
menu = st.sidebar.selectbox("Navigation", ["Dashboard", "Submit Report", "Attachment & Audit", "Lookups", "Extract Links"])

# Try detect local tz for convenience
try:
    detected_tz = get_localzone_name()
except Exception:
    detected_tz = "UTC"

# -------------------------
# Dashboard
# -------------------------
if menu == "Dashboard":
    st.title("Scam Report Dashboard")

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        t_filter = st.selectbox("Type", options=["all", "sms", "call", "email"])
    with col2:
        s_filter = st.selectbox("Status", options=["all", "new", "triaged", "actioned", "false_positive"])
    with col3:
        q = st.text_input("Keyword (message, source, ocr)")

    stmt = select(
        reports.c.id, reports.c.type, reports.c.reported_via, reports.c.source_from,
        reports.c.message_content, reports.c.ocr_preview, reports.c.report_status,
        reports.c.pose_as_id, reports.c.received_at, reports.c.received_at_tz, reports.c.created_on
    ).where(reports.c.deleted == False).order_by(reports.c.created_on.desc()).limit(200)

    if t_filter != "all":
        stmt = stmt.where(reports.c.type == t_filter)
    if s_filter != "all":
        stmt = stmt.where(reports.c.report_status == s_filter)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(
            reports.c.message_content.ilike(like),
            reports.c.source_from.ilike(like),
            reports.c.ocr_preview.ilike(like)
        ))

    rows, keys = safe_rows(stmt)
    df = pd.DataFrame(rows, columns=keys) if rows else pd.DataFrame(columns=keys or [])

    st.markdown(f"**Showing {len(df)} reports**")

    if not df.empty:
        # preload pose display names
        pose_map = {}
        if posing_as is not None:
            pr, _ = safe_rows(select(posing_as.c.id, posing_as.c.display_name).where(posing_as.c.deleted == False))
            pose_map = {r[0]: r[1] for r in pr}

        for _i, r in df.iterrows():
            utc_dt = r["received_at"] or r["created_on"]
            tz_name = r.get("received_at_tz") or None
            # ensure utc_dt is timezone aware; SQLAlchemy should return tz-aware, but ensure fallback
            if utc_dt and utc_dt.tzinfo is None:
                utc_dt = utc_dt.replace(tzinfo=pytz.utc)
            local_dt = convert_utc_to_local(utc_dt, tz_name) if utc_dt else None
            local_display = local_dt.strftime("%Y-%m-%d %H:%M:%S %Z") if local_dt else "unknown"
            utc_display = utc_dt.strftime("%Y-%m-%d %H:%M:%S %Z") if utc_dt else "unknown"
            pose_display = pose_map.get(r["pose_as_id"], None)

            with st.expander(f"{r['type'].upper()} • {r['source_from'] or 'unknown'} • {local_display}"):
                st.write("**Message**")
                st.write(r["message_content"] or r["ocr_preview"] or "_(no content)_")
                st.write(f"**Received at (local)**: {local_display} (stored tz: {tz_name or 'none'})")
                st.write(f"**Received at (UTC)**: {utc_display}")
                st.write("**Status**:", r["report_status"])
                if pose_display:
                    st.write("**Pose as**:", pose_display)

                # Audit actions
                aud_rows, _ = safe_rows(
                    select(report_audit.c.action, report_audit.c.comment, report_audit.c.performed_by, report_audit.c.created_on)
                    .where(and_(report_audit.c.report_id == r["id"], report_audit.c.deleted == False))
                    .order_by(report_audit.c.created_on.desc())
                )
                if aud_rows:
                    st.write("**Audit Trail**")
                    for a in aud_rows:
                        created = a[3]
                        if created and created.tzinfo is None:
                            created = created.replace(tzinfo=pytz.utc)
                        st.write(f"- {created} • **{a[0]}** by {a[2]} — {a[1]}")
                else:
                    st.write("_No audit actions_")

                # Links
                link_rows, _ = safe_rows(
                    select(report_links.c.url, report_links.c.safety)
                    .where(and_(report_links.c.report_id == r["id"], report_links.c.deleted == False))
                )
                if link_rows:
                    st.write("**Links**")
                    for l in link_rows:
                        st.write(f"- {l[0]} [{l[1] or 'unknown'}]")

# -------------------------
# Submit Report
# -------------------------
elif menu == "Submit Report":
    st.title("Submit New Report")

    with st.form("report_form"):
        type_val = st.selectbox("Type", ["sms", "call", "email"])
        reported_via = st.selectbox("Reported via", ["self", "web", "app"])
        source_from = st.text_input("Source (phone or email)")
        subject = st.text_input("Subject (optional)")
        message_content = st.text_area("Message content", height=140)

        # Local date & time capture and timezone select
        cold, colt, coltz = st.columns([2, 2, 2])
        with cold:
            local_date = st.date_input("Local date", value=datetime.utcnow().date())
        with colt:
            local_time = st.time_input("Local time", value=datetime.utcnow().time().replace(microsecond=0))
        # timezone choices: detected first, then all
        tz_choices = [detected_tz] + [tz for tz in pytz.all_timezones if tz != detected_tz]
        with coltz:
            user_tz = st.selectbox("Timezone", tz_choices, index=0)

        # pose_as
        pose_id = None
        if posing_as is not None:
            pr, _ = safe_rows(select(posing_as.c.id, posing_as.c.display_name).where(posing_as.c.deleted == False).order_by(posing_as.c.id))
            pose_options = [(None, "None")] + [(r[0], r[1]) for r in pr]
            pose_labels = [p[1] for p in pose_options]
            sel = st.selectbox("Pose as", pose_labels)
            pose_id = next((p[0] for p in pose_options if p[1] == sel), None)

        contain_link = st.checkbox("Contains link")
        link_url = st.text_input("Link URL") if contain_link else ""
        screenshot = st.file_uploader("Screenshot (optional)", type=["png", "jpg", "jpeg"])
        submit = st.form_submit_button("Submit")

    if submit:
        # Build naive datetime then convert to UTC
        naive_local_dt = datetime.combine(local_date, local_time)
        utc_dt = convert_local_to_utc(naive_local_dt, user_tz)
        now_utc = datetime.now(pytz.utc)

        payload = {
            "type": type_val,
            "reported_via": reported_via,
            "received_at": utc_dt,
            "received_at_tz": user_tz,
            "source_from": source_from or None,
            "subject": subject or None,
            "message_content": message_content or None,
            "pose_as_id": int(pose_id) if pose_id is not None else None,
            "contain_link": bool(contain_link),
            "screenshot": screenshot.read() if screenshot else None,
            "screenshot_mime": screenshot.type if screenshot else None,
            "screenshot_size": screenshot.size if screenshot else None,
            "ocr_preview": None,
            "spam_score": None,
            "source_ip": None,
            "report_status": "new",
            "processing_flags": [],
            "created_on": now_utc,
            "updated_on": now_utc,
            "deleted": False
        }

        new_id = insert_and_return_id(reports, payload)
        if new_id and contain_link and link_url:
            insert_simple(report_links, {
                "report_id": new_id,
                "url": link_url,
                "domain": urlparse(link_url).netloc or link_url,
                "safety": None,
                "created_on": now_utc,
                "updated_on": now_utc,
                "deleted": False
            })
        if new_id:
            st.success(f"Report inserted: {new_id} (received_at UTC: {utc_dt.isoformat()})")

# -------------------------
# Attachment & Audit
# -------------------------
elif menu == "Attachment & Audit":
    st.title("Upload Attachment or Log Audit Action")

    report_rows, _ = safe_rows(select(reports.c.id, reports.c.source_from).where(reports.c.deleted == False).order_by(reports.c.created_on.desc()).limit(200))
    user_rows, _ = safe_rows(select(users.c.id, users.c.display_name).where(users.c.deleted == False).order_by(users.c.display_name))

    report_map = {r[0]: (r[1] or str(r[0])) for r in report_rows}
    with st.form("attach_audit"):
        report_id = st.selectbox("Report", options=list(report_map.keys()), format_func=lambda x: f"{report_map[x]} ({x})")
        attach_type = st.selectbox("Attachment type", ["none", "audio", "raw_eml", "transcript"])
        uploaded = st.file_uploader("File (optional)")
        performed_by = st.selectbox("Performed by", options=[None] + [u[0] for u in user_rows], format_func=lambda x: "System" if x is None else next((u[1] for u in user_rows if u[0]==x), str(x)))
        action = st.selectbox("Audit action", ["none", "triage", "forward", "delete"])
        comment = st.text_area("Comment")
        submit2 = st.form_submit_button("Submit")

    if submit2:
        now_utc = datetime.now(pytz.utc)
        if uploaded and attach_type != "none":
            os.makedirs("uploads", exist_ok=True)
            fname = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uploaded.name}"
            fpath = os.path.join("uploads", fname)
            with open(fpath, "wb") as f:
                f.write(uploaded.read())
            insert_simple(attachments, {
                "report_id": report_id,
                "type": attach_type,
                "storage_path": fpath,
                "checksum": None,
                "mime_type": uploaded.type,
                "size_bytes": os.path.getsize(fpath),
                "transcript": None,
                "created_on": now_utc,
                "updated_on": now_utc,
                "deleted": False
            })
            st.success("Attachment saved")
        if action != "none":
            insert_simple(report_audit, {
                "report_id": report_id,
                "performed_by": performed_by,
                "action": action,
                "comment": comment,
                "created_on": now_utc,
                "updated_on": now_utc,
                "deleted": False
            })
            if action == "delete":
                try:
                    with engine.begin() as conn:
                        conn.execute(reports.update().where(reports.c.id==report_id).values(deleted=True, deleted_on=now_utc, updated_on=now_utc))
                except SQLAlchemyError as e:
                    st.error(f"Error marking report deleted: {e}")
            st.success("Audit logged")

# -------------------------
# Lookups
# -------------------------
elif menu == "Lookups":
    st.title("Lookup tables")
    if posing_as is not None:
        rows, keys = safe_rows(select(posing_as.c.id, posing_as.c.code, posing_as.c.display_name, posing_as.c.description).where(posing_as.c.deleted == False))
        st.subheader("Posing As")
        st.table(pd.DataFrame(rows, columns=keys))
    if users is not None:
        rows, keys = safe_rows(select(users.c.id, users.c.display_name, users.c.contact).where(users.c.deleted == False))
        st.subheader("Users")
        st.table(pd.DataFrame(rows, columns=keys))


# -------------------------
# Extract Links
# -------------------------

def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s<>"\'\)\]]+|(?:www\.)?[a-zA-Z0-9.-]+\.[a-z]{2,}(?:/[^\s]*)?', text)


if menu == "Extract Links":
    st.title("Link Extraction from Reports")
    st.write("This will scan recent reports with `contain_link = true` and extract URLs from message content and OCR preview.")

    if st.button("Run extraction"):
        stmt = select(
            reports.c.id, reports.c.message_content, reports.c.ocr_preview
        ).where(
            and_(reports.c.contain_link == True, reports.c.deleted == False)
        ).order_by(reports.c.created_on.desc()).limit(200)

        rows, _ = safe_rows(stmt)
        inserted = 0
        skipped = 0

        for r in rows:
            rid = r[0]
            text = (r[1] or "") + "\n" + (r[2] or "")
            urls = extract_urls(text)

            if not urls:
                continue

            # Check existing links
            existing_rows, _ = safe_rows(select(report_links.c.url).where(report_links.c.report_id == rid))
            existing_urls = set([row[0] for row in existing_rows])

            for url in urls:
                if url in existing_urls:
                    skipped += 1
                    continue
                insert_simple(report_links, {
                    "report_id": rid,
                    "url": url,
                    "domain": urlparse(url).netloc or url,
                    "safety": None,
                    "created_on": datetime.utcnow(),
                    "updated_on": datetime.utcnow(),
                    "deleted": False
                })
                inserted += 1

        st.success(f"Extraction complete. {inserted} new links inserted. {skipped} duplicates skipped.")
