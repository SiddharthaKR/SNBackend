from sqlalchemy import Column, Integer, String, Boolean, Text
from database import Base
from pydantic import BaseModel



class AppDBModel(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String(length=255), nullable=True)  # Specify the length for VARCHAR
    app_name = Column(String(length=255), nullable=True)  # Specify the length for VARCHAR
    version_code = Column(Integer, nullable=True)
    version_name = Column(String(length=255),nullable=True)  # Specify the length for VARCHAR
    file_size = Column(Integer,nullable=True)
    permissions = Column(Text,nullable=True)
    is_system_app = Column(Boolean)
    is_malicious = Column(Boolean)
    threat_category = Column(String(length=255), nullable=True)  # Specify the length for VARCHAR
    static_analysis_results = Column(Text, nullable=True)
    dynamic_analysis_results = Column(Text, nullable=True)