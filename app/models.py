from sqlalchemy import Column, Integer, Text, DateTime, Boolean, ForeignKey, BigInteger
from sqlalchemy.sql import func

from .db import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_type = Column(Text, nullable=False)  # sms | email | call
    source_from = Column(Text)  # phone number or email address
    subject = Column(Text)
    message_content = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True))

    reporter_name = Column(Text)
    reporter_contact = Column(Text)

    suggested_classification = Column(Text, nullable=False, server_default="unclassified")
    classification = Column(Text, nullable=False, server_default="unclassified")
    classified_by = Column(Text)
    classified_on = Column(DateTime(timezone=True))

    is_verified = Column(Boolean, server_default="false", nullable=False)
    verified_by = Column(Text)
    verified_on = Column(DateTime(timezone=True))

    is_flagged = Column(Boolean, server_default="false", nullable=False)
    flag_reason = Column(Text)
    flagged_on = Column(DateTime(timezone=True))
    flagged_by = Column(Text)

    created_on = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_on = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    deleted = Column(Boolean, server_default="false", nullable=False)


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    original_name = Column(Text, nullable=False)
    storage_path = Column(Text, nullable=False)
    mime_type = Column(Text)
    size_bytes = Column(BigInteger)

    created_on = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    deleted = Column(Boolean, server_default="false", nullable=False)
