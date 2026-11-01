"""Platform-only fixtures; optional extras must not break scanner-only installs."""

import pytest


@pytest.fixture
def platform(tmp_path):
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("authlib")
    import os
    import uuid

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from silentsec.platform import billing
    from silentsec.platform.__main__ import migrate
    from silentsec.platform.app import create_app
    from silentsec.platform.auth.routes import provision_org
    from silentsec.platform.config import Settings
    from silentsec.platform.models import PlatformRole, User

    database_url = "sqlite:///" + (tmp_path / "platform.db").as_posix()
    postgres = os.environ.get("SILENTSEC_TEST_POSTGRES_URL")
    schema = "ssec_test_" + uuid.uuid4().hex
    admin_engine = None
    if postgres:
        admin_engine = create_engine(postgres, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        database_url = (
            make_url(postgres)
            .update_query_dict({"options": "-csearch_path=" + schema})
            .render_as_string(hide_password=False)
        )
    settings = Settings(
        environment="test",
        auth_mode="development",
        session_secret="s" * 64,
        dev_login_code="local-test-access-code",
        data_dir=tmp_path,
        database_url=database_url,
        public_url="http://127.0.0.1:8780",
        auto_worker=False,
    )
    migrate(settings)
    app = create_app(settings)
    factory = app.state.factory
    with factory.begin() as db:
        billing.seed_plans(db)

    clients = []

    def account(email, admin=False, login_admin=False):
        with factory.begin() as db:
            user = User(email=email, issuer="development", subject=email, name=email.split("@")[0])
            db.add(user)
            db.flush()
            org = provision_org(db, user, user.name + " workspace")
            if admin:
                db.add(PlatformRole(user_id=user.id, role="platform_admin"))
        client = TestClient(app, base_url=settings.public_url, headers={"Origin": settings.origin})
        response = client.post(
            "/api/v1/auth/dev",
            json={"email": email, "access_code": "local-test-access-code", "admin": login_admin},
        )
        assert response.status_code == 200, response.text
        me = client.get("/api/v1/auth/me").json()
        client.headers["X-CSRF-Token"] = me["csrf_token"]
        clients.append(client)
        return client, user.id, org.id

    yield app, factory, account, settings
    for client in clients:
        client.close()
    app.state.engine.dispose()
    if admin_engine:
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
