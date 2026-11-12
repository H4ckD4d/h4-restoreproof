from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Integer, Boolean
from .db import Base, uid

class Backup(Base):
    __tablename__='backups'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    label: Mapped[str]=mapped_column(String(120))
    sha256: Mapped[str]=mapped_column(String(64))
    size_bytes: Mapped[int]=mapped_column(Integer)

class Check(Base):
    __tablename__='integrity_checks'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    backup_id: Mapped[str]=mapped_column(String(36),index=True)
    matched: Mapped[bool]=mapped_column(Boolean)
    observed_sha256: Mapped[str]=mapped_column(String(64))
