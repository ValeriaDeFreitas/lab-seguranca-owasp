import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('XSS')</script>"
    }
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }
    resposta = cliente.post("/seguro/login", json=payload_malicioso)
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"

@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('Ataque XSS')</script>"
    }
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<script>" not in conteudo_retornado
    assert "&lt;script&gt;" in conteudo_retornado