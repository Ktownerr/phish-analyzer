"""
Database layer. Uses SQLAlchemy so swapping between SQLite (quick local
dev) and PostgreSQL (production on the Ubuntu VM) is just an env var.

Set DATABASE_URL, e.g.:
  postgresql+psycopg2://phishapp:password@localhost:5432/phishdb
If unset, falls back to a local SQLite file for easy first-run testing.
"""

import os
import json
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./phishapp.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), index=True)
    subject = Column(String(998), default="")
    from_address = Column(String(320), default="")
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="Minimal")
    result_json = Column(Text)  # full analysis result, stored as JSON
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def save_analysis(username: str, result: dict):
    session = SessionLocal()
    try:
        record = Analysis(
            username=username,
            subject=result["headers"].get("subject", ""),
            from_address=result["headers"].get("from_address", ""),
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            result_json=json.dumps(result),
        )
        session.add(record)
        session.commit()
    finally:
        session.close()


def get_history(username: str, limit: int = 25):
    session = SessionLocal()
    try:
        rows = (
            session.query(Analysis)
            .filter(Analysis.username == username)
            .order_by(Analysis.created_at.desc())
            .limit(limit)
            .all()
        )
        return rows
    finally:
        session.close()
