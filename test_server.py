import app
import json

def test_jwks():
    client = app.app.test_client()
    res = client.get("/jwks")
    assert res.status_code == 200
    assert "keys" in json.loads(res.data)


def test_auth():
    client = app.app.test_client()
    res = client.post("/auth")
    assert res.status_code == 200
    assert "token" in json.loads(res.data)


def test_expired_auth():
    client = app.app.test_client()
    res = client.post("/auth?expired=true")
    assert res.status_code == 200
    assert "token" in json.loads(res.data)