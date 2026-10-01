from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(255), unique=True, nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False, index=True)  # url, ip, domain, sha256
    threat_type = Column(String(100), default="unknown")       # botnet_c2, malware_delivery
    confidence_score = Column(Float, default=0.0)
    source = Column(String(100), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    description = Column(Text, nullable=True)
    
    # Geographic Enrichment Fields
    country = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    vendor_project = Column(String(100), nullable=False, index=True)
    product = Column(String(100), nullable=False)
    vulnerability_name = Column(String(255), nullable=True)
    date_added = Column(String(50), nullable=True)
    short_description = Column(Text, nullable=True)

DATABASE_URL = "sqlite:///threat_intel.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("[✓] Schema updated successfully in threat_intel.db")
