"""Bounded MVP API. Never deploy this demo unchanged with real customer data."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta, date
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Base, AuditEvent, audit, engine_for_env, uid
from .security import current_actor
from .model import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = engine_for_env()
    app.state.engine = engine
    if os.getenv('H4_AUTO_CREATE_TABLES') == '1':
        Base.metadata.create_all(engine)
    try:
        yield
    finally:
        engine.dispose()

def session_dep(request: Request):
    with Session(request.app.state.engine) as session:
        yield session

def require_tenant(session: Session, model, entity_id: str, tenant_id: str):
    item = session.scalar(select(model).where(model.id == entity_id, model.tenant_id == tenant_id))
    if item is None:
        raise HTTPException(404, 'Not found')
    return item

app = FastAPI(title='H4 RestoreProof', version='0.1.0', lifespan=lifespan,
              description='Tenant-scoped technical MVP; not production-ready.')

@app.middleware('http')
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.get('/healthz', include_in_schema=False)
def healthz():
    return {'ok': True}

@app.get('/v1/audit')
def audit_list(auth=Depends(current_actor), session: Session=Depends(session_dep)):
    rows = session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == auth['tenant_id'])
                           .order_by(AuditEvent.created_at.desc()).limit(100)).all()
    return {'events': [{'kind': r.kind, 'resource_id': r.resource_id,
                        'actor_id': r.actor_id, 'at': r.created_at.isoformat()} for r in rows]}

import hashlib
import re

class BackupCreate(BaseModel):
    label: str=Field(min_length=2,max_length=120)
    sha256: str=Field(pattern='^[0-9a-f]{64}$')
    size_bytes: int=Field(ge=0,le=10**13)

@app.post('/v1/backups',status_code=201)
def create_backup(payload: BackupCreate,auth=Depends(current_actor),session: Session=Depends(session_dep)):
    backup=Backup(tenant_id=auth['tenant_id'],**payload.model_dump())
    session.add(backup);session.flush();audit(session,auth,'backup.registered',backup.id);session.commit()
    return {'id':backup.id,'sha256':backup.sha256,'size_bytes':backup.size_bytes}

@app.post('/v1/backups/{backup_id}/verify')
async def verify_backup(backup_id: str,request: Request,auth=Depends(current_actor),session: Session=Depends(session_dep)):
    backup=require_tenant(session,Backup,backup_id,auth['tenant_id'])
    # Demo refuses large uploads; stream rather than storing backup bytes.
    hasher=hashlib.sha256(); length=0; max_bytes=16*1024*1024
    async for chunk in request.stream():
        length+=len(chunk)
        if length>max_bytes:
            raise HTTPException(413,'Verification upload exceeds 16 MiB demo limit')
        hasher.update(chunk)
    observed=hasher.hexdigest(); matched=observed==backup.sha256 and length==backup.size_bytes
    check=Check(tenant_id=auth['tenant_id'],backup_id=backup.id,matched=matched,observed_sha256=observed)
    session.add(check);session.flush();audit(session,auth,'backup.integrity_checked',check.id);session.commit()
    return {'check_id':check.id,'matched':matched,'observed_sha256':observed,'bytes_received':length,
            'note':'Integrity check only. No restore or recovery-time testing was performed.'}

@app.get('/v1/backups/{backup_id}/checks')
def checks(backup_id: str,auth=Depends(current_actor),session: Session=Depends(session_dep)):
    require_tenant(session,Backup,backup_id,auth['tenant_id'])
    rows=session.scalars(select(Check).where(Check.tenant_id==auth['tenant_id'],Check.backup_id==backup_id).limit(100)).all()
    return [{'id':r.id,'matched':r.matched,'observed_sha256':r.observed_sha256} for r in rows]
