from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

SQLALCHEMY_DATABASE_URL = "sqlite:///./memguard.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True)
    name = Column(String)
    device_type = Column(String, index=True) # WINDOWS, LINUX, MACOS, ANDROID, IOS, WEB
    ip_address = Column(String)
    os_info = Column(String)
    status = Column(String, default="ONLINE") # ONLINE, COMPROMISED, WARNING, OFFLINE
    risk_score = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    last_seen = Column(DateTime, default=datetime.utcnow)
    meta_info = Column(JSON, nullable=True)

class ThreatIncident(Base):
    __tablename__ = "threat_incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, unique=True, index=True)
    device_id = Column(String, index=True)
    process_name = Column(String)
    pid = Column(Integer, nullable=True)
    severity = Column(String, default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    score = Column(Integer, default=50)
    threat_title = Column(String)
    cmdline = Column(Text, nullable=True)
    mitre_technique = Column(String, nullable=True)
    status = Column(String, default="ACTIVE") # ACTIVE, CONTAINED, RESOLVED
    timestamp = Column(DateTime, default=datetime.utcnow)
    raw_details = Column(JSON, nullable=True)

class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String, unique=True, index=True)
    device_id = Column(String, nullable=True) # None = Fleet-Wide
    title = Column(String)
    risk_level = Column(String)
    total_score = Column(Integer)
    threats_found = Column(Integer)
    executive_summary = Column(Text)
    recommendations = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    full_report_data = Column(JSON)

class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String, index=True)
    source = Column(String)
    message = Column(String)
    details = Column(JSON, nullable=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    role = Column(String)  # ADMIN, HOST, USER
    password_hash = Column(String)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

