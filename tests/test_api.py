import hashlib, json, os
import pytest
from fastapi.testclient import TestClient
from . import TEST_APP

KEY_A='tenantA_sample_key_0123456789ABCDEFG'
KEY_B='tenantB_sample_key_0123456789ABCDEFG'
KEY_REVIEWER='tenantA_reviewer_key_0123456789ABC'
KEY_SECOND='tenantA_second_reviewer_0123456789'
KEY_VIEWER='tenantA_viewer_readonly_0123456789AB'
KEY_HASHED='tenantA_hashed_credential_0123456789AB'
KEY_DISABLED='tenantA_revoked_credential_0123456789AB'

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('H4_DATABASE_URL',f'sqlite:///{tmp_path / "db.sqlite"}')
    monkeypatch.setenv('H4_AUTO_CREATE_TABLES','1')
    monkeypatch.setenv('H4_TENANTS',json.dumps([
        {'tenant_id':'t-a','actor_id':'owner','role':'admin','key':KEY_A},
        {'tenant_id':'t-a','actor_id':'reviewer','role':'editor','key':KEY_REVIEWER},
        {'tenant_id':'t-a','actor_id':'second','role':'editor','key':KEY_SECOND},
        {'tenant_id':'t-b','actor_id':'ownerB','role':'admin','key':KEY_B},
        {'tenant_id':'t-a','actor_id':'observer','role':'viewer','key':KEY_VIEWER},
        {'tenant_id':'t-a','actor_id':'hashed','role':'viewer','key_sha256':hashlib.sha256(KEY_HASHED.encode()).hexdigest()},
        {'tenant_id':'t-a','actor_id':'revoked','role':'admin','key':KEY_DISABLED,'disabled':True},
    ]))
    with TestClient(TEST_APP) as c:
        yield c

def headers(key=KEY_A):
    return {'X-API-Key':key}

def test_security(client):
    assert client.get('/healthz').status_code==200
    assert client.get('/v1/audit').status_code==401
    assert client.get('/v1/audit', headers=headers('invalid')).status_code==401
    assert client.get('/v1/audit', headers=headers()).status_code==200
    assert client.get('/v1/audit', headers=headers()).headers['Cache-Control']=='no-store'

def test_integrity_verification_and_tenant_scope(client):
    data=b'FAKE BACKUP BYTES ONLY'; digest=hashlib.sha256(data).hexdigest()
    result=client.post('/v1/backups',json={'label':'Demo backup','sha256':digest,'size_bytes':len(data)},headers=headers())
    assert result.status_code==201,result.text
    id=result.json()['id']
    assert client.post(f'/v1/backups/{id}/verify',content=data,headers=headers(KEY_B)).status_code==404
    assert client.post(f'/v1/backups/{id}/verify',content=data,headers=headers()).json()['matched']
    assert not client.post(f'/v1/backups/{id}/verify',content=b'changed',headers=headers()).json()['matched']
    assert len(client.get(f'/v1/backups/{id}/checks',headers=headers()).json())==2

def test_bad_digest_fails(client):
    assert client.post('/v1/backups',json={'label':'fake','sha256':'bad','size_bytes':1},headers=headers()).status_code==422

def test_audit_visibility_is_tenant_scoped(client):
    from sqlalchemy.orm import Session
    from . import TEST_APP
    from restoreproof.db import AuditEvent

    with Session(TEST_APP.state.engine) as session:
        session.add(AuditEvent(tenant_id='t-a',actor_id='owner',kind='synthetic',resource_id='a'))
        session.add(AuditEvent(tenant_id='t-b',actor_id='ownerB',kind='synthetic',resource_id='b'))
        session.commit()
    a=client.get('/v1/audit',headers=headers(KEY_A)).json()['events']
    b=client.get('/v1/audit',headers=headers(KEY_B)).json()['events']
    assert [x['resource_id'] for x in a]==['a']
    assert [x['resource_id'] for x in b]==['b']

def test_missing_auth_config_fails_closed(client, monkeypatch):
    monkeypatch.delenv('H4_TENANTS')
    response=client.get('/v1/audit',headers=headers(KEY_A))
    assert response.status_code==503

def test_viewer_and_hashed_keys(client):
    assert client.get('/v1/audit',headers=headers(KEY_VIEWER)).status_code==200
    assert client.get('/v1/audit',headers=headers(KEY_HASHED)).status_code==200
    assert client.get('/v1/audit',headers=headers(KEY_DISABLED)).status_code==401

def test_audit_pagination_bounds(client):
    assert client.get('/v1/audit?limit=1&offset=0',headers=headers()).status_code==200
    assert client.get('/v1/audit?limit=101',headers=headers()).status_code==422
    assert client.get('/v1/audit?offset=-1',headers=headers()).status_code==422

def test_viewer_readonly(client):
    assert client.post('/v1/backups',json={'label':'Test backup','sha256':hashlib.sha256(b'x').hexdigest(),'size_bytes':1},headers=headers(KEY_VIEWER)).status_code==403

def test_ambiguous_credentials_fail_closed(client,monkeypatch):
    entries=[{'tenant_id':'x','actor_id':'a','role':'admin','key':KEY_A},
             {'tenant_id':'y','actor_id':'b','role':'admin','key':KEY_A}]
    monkeypatch.setenv('H4_TENANTS',json.dumps(entries))
    assert client.get('/v1/audit',headers=headers(KEY_A)).status_code==503

def test_backup_listing_and_summary_isolation(client):
    data=b'FAKE-RESTORE-DATA'; digest=hashlib.sha256(data).hexdigest()
    backup=client.post('/v1/backups',json={'label':'Sample','sha256':digest,'size_bytes':len(data)},headers=headers()).json()['id']
    client.post(f'/v1/backups/{backup}/verify',content=data,headers=headers())
    assert client.get('/v1/backups',headers=headers(KEY_VIEWER)).json()['backups'][0]['id']==backup
    assert client.get('/v1/backups',headers=headers(KEY_B)).json()['backups']==[]
    assert client.get(f'/v1/backups/{backup}/summary',headers=headers(KEY_B)).status_code==404
    assert client.get(f'/v1/backups/{backup}/summary',headers=headers()).json()['matching']==1
