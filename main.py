import html
import sqlite3
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Hub Solidario - Laboratorio de Seguranca")

def obter_banco():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comentarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            conteudo TEXT NOT NULL
        )
    """)
    cursor.execute("""
        INSERT INTO usuarios (nome, email, senha, is_admin)
        VALUES 
            ('Administrador', 'admin@hubsolidario.org', 'segredo_admin_123', 1),
            ('Voluntario Lucas', 'lucas@voluntariado.org', 'senha_lucas_456', 0)
    """)
    conn.commit()
    return conn

db = obter_banco()

class RequisicaoLogin(BaseModel):
    email: str
    senha: str

class RequisicaoComentario(BaseModel):
    autor: str
    conteudo: str

# Endpoints Vulneráveis
@app.post("/vulneravel/login")
def login_vulneravel(dados: RequisicaoLogin):
    cursor = db.cursor()
    query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
    cursor.execute(query)
    usuario = cursor.fetchone()
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")
    return {"id": usuario[0], "nome": usuario[1], "email": usuario[2], "is_admin": bool(usuario[3]), "status": "Autenticado"}

@app.post("/vulneravel/comentarios")
def comentar_vulneravel(dados: RequisicaoComentario):
    cursor = db.cursor()
    cursor.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (dados.autor, dados.conteudo))
    db.commit()
    return {"autor": dados.autor, "conteudo": dados.conteudo}

# Endpoints Seguros
@app.post("/seguro/login")
def login_seguro(dados: RequisicaoLogin):
    cursor = db.cursor()
    query = "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?"
    cursor.execute(query, (dados.email, dados.senha))
    usuario = cursor.fetchone()
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")
    return {"id": usuario[0], "nome": usuario[1], "email": usuario[2], "is_admin": bool(usuario[3]), "status": "Autenticado"}

@app.post("/seguro/comentarios")
def comentar_seguro(dados: RequisicaoComentario):
    autor_seguro = html.escape(dados.autor.strip())
    conteudo_seguro = html.escape(dados.conteudo.strip())
    cursor = db.cursor()
    cursor.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (autor_seguro, conteudo_seguro))
    db.commit()
    return {"autor": autor_seguro, "conteudo": conteudo_seguro}