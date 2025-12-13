from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# --- Database Setup ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "dns_logs.db")
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"

# Fix: Added timeout=15 to handle file locking delays
engine = create_engine(
    SQLALCHEMY_DATABASE_URI, 
    connect_args={"check_same_thread": False, "timeout": 15}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Model Definition ---
class DnsLog(Base):
    __tablename__ = "dns_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    display_time = Column(String(20)) 
    domain = Column(String(255), index=True)
    ip = Column(String(50))
    status = Column(String(20))
    message = Column(Text)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": self.domain,
            "ip": self.ip,
            "status": self.status,
            "message": self.message
        }

# --- Helper Functions ---
def init_db():
    Base.metadata.create_all(bind=engine)

def save_log_entry(data):
    session = SessionLocal()
    try:
        new_entry = DnsLog(
            display_time=data.get('timestamp'),
            domain=data.get('domain'),
            ip=data.get('ip'),
            status=data.get('status'),
            message=data.get('message')
        )
        session.add(new_entry)
        session.commit()
    except Exception as e:
        print(f"[DB ERROR] Could not save log: {e}")
        session.rollback()
    finally:
        session.close()

def get_recent_logs(limit=100):
    session = SessionLocal()
    try:
        logs = session.query(DnsLog).order_by(DnsLog.timestamp.desc()).limit(limit).all()
        return [log.to_dict() for log in logs]
    finally:
        session.close()