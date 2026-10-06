# Plano e Matriz de Segurança da API

**Sistema para Controle de Estoque de Pastilhas Industriais — DDA Metalúrgica**

## Sumário

1. [Objetivo e escopo](#1-objetivo-e-escopo)
2. [Matriz de Segurança](#2-matriz-de-segurança)
3. [Plano de Segurança da API](#3-plano-de-segurança-da-api)
4. [Perfis e Permissões](#4-perfis-e-permissões)
5. [Respostas HTTP relacionadas à segurança](#5-respostas-http-relacionadas-à-segurança)
6. [Testes de segurança previstos](#6-testes-de-segurança-previstos)
7. [Considerações finais](#7-considerações-finais)

---

## 1. Objetivo e escopo

Este documento registra as decisões de segurança previstas para a API do Sistema para Controle de Estoque de Pastilhas Industriais da DDA Metalúrgica e servirá de referência para a futura implementação com **Spring Security**. As medidas descritas são propostas e deverão ser configuradas e testadas durante o desenvolvimento.

O escopo abrange autenticação, usuários e perfis, pastilhas, fabricantes, fornecedores, estoque, movimentações e relatórios.

**Premissas adotadas:**

- a API será consumida por um frontend web e, em produção, acessada somente por HTTPS;
- existem dois perfis autenticados, Operador e Administrador; a pessoa não autenticada acessa apenas o login;
- a classificação de risco da matriz é preliminar e deve ser revisada junto à DDA Metalúrgica.

---

## 2. Matriz de Segurança

A coluna **Risco** indica a prioridade preliminar de tratamento (Alto, Médio ou Baixo), considerando a probabilidade da ameaça e o impacto possível.

| Recurso/operação | Ameaça | Impacto possível | Controle preventivo | Risco |
|---|---|---|---|---|
| `POST /auth/login` | Força bruta, credential stuffing e enumeração de usuários (mensagens ou tempos de resposta diferentes). | Acesso indevido a contas e dados. | Hash seguro de senhas (BCrypt/Argon2); limite de tentativas com bloqueio temporário; mensagem de erro genérica; tamanho mínimo de senha; HTTPS; registro de eventos suspeitos. | Alto |
| Endpoints protegidos (JWT) | Token ausente, inválido, expirado, forjado ou roubado. | Acesso não autorizado e alteração de informações. | JWT Bearer; validar assinatura, expiração e algoritmo esperado; chave de assinatura forte e fora do código; expiração curta; sem dados sensíveis no payload; HTTPS; responder 401 quando não autenticado. | Alto |
| Autorização por perfil (todos os endpoints) | Usuário executando função de outro perfil (ex.: operador em ação administrativa) ou regra aplicada apenas na interface. | Alteração ou exclusão indevida de dados. | RBAC aplicado no backend; negar por padrão; responder 403 a usuário autenticado sem permissão; testes de acesso permitido e negado por perfil. | Alto |
| `GET /pastilhas` e `GET /estoque` | Exposição excessiva de dados ou acesso indevido. | Divulgação de informações operacionais. | Exigir autenticação; autorização por perfil; DTOs de resposta apenas com os dados necessários; paginação. | Médio |
| `POST/PUT/DELETE /pastilhas` | SQL Injection, dados inválidos, envio de campos não previstos (mass assignment) e exclusão indevida. | Corrupção de cadastros e perda de referências. | Validar entradas; DTOs de entrada apenas com os campos permitidos; ORM/consultas parametrizadas; restringir escrita ao administrador; validar vínculos e unicidade. | Alto |
| Fabricantes e fornecedores | SQL Injection, dados inconsistentes ou exclusão de registros vinculados. | Cadastros incorretos e relacionamentos quebrados. | Validar formato e tamanho; consultas parametrizadas; restringir alterações ao administrador; impedir exclusão com vínculos (409). | Médio |
| `POST /movimentacoes` | Quantidade ou tipo manipulados; saída maior que o saldo; requisições concorrentes ou duplicadas. | Saldo incorreto e falta de materiais. | Quantidade positiva e tipo permitido; transação; controle de concorrência; impedir saldo negativo; registrar autor e data; avaliar chave de idempotência contra envio duplicado. | Alto |
| Correção de movimentações (histórico) | Alteração ou exclusão de lançamentos para ocultar erros ou desvios; negação de autoria. | Perda de rastreabilidade e saldo inconsistente. | Movimentações imutáveis (sem PUT/DELETE); correção por lançamento de ajuste ou estorno com justificativa; registrar usuário e data/hora; restringir acesso à trilha. | Médio |
| `GET /movimentacoes` e relatórios | Consulta excessiva ou acesso por perfil inadequado. | Exposição do histórico e sobrecarga. | Exigir autenticação; limitar período e paginar; validar filtros; aplicar permissões por tipo de relatório. | Médio |
| `PUT /estoque/{pastilhaId}/minimo` | Alteração não autorizada ou valor negativo. | Alertas e planejamento de reposição incorretos. | Somente administrador; inteiro maior ou igual a zero; registrar a alteração. | Baixo |
| Gestão de usuários e perfis | Escalada de privilégios, criação de contas indevidas ou usuário alterando o próprio perfil. | Controle indevido do sistema. | Somente administrador; ignorar perfil enviado por usuário comum; nunca retornar senha ou hash; desativar contas em vez de excluir; registrar alterações. | Alto |
| Campos de texto exibidos na interface | XSS por conteúdo malicioso armazenado. | Execução de script no cliente se o conteúdo for interpretado como HTML. | Validar formato e tamanho; escapar dados na interface; não inserir conteúdo como HTML; CSP na aplicação web, quando aplicável. | Médio |
| Comunicação frontend/API | CORS permissivo ou origem não autorizada. | Chamadas feitas por origens não previstas no navegador. | Permitir apenas origens conhecidas; restringir métodos e cabeçalhos; não combinar wildcard com credenciais. CORS não substitui autenticação. | Médio |
| Autenticação por navegador | CSRF caso sejam usados cookies enviados automaticamente. | Operação executada sem intenção do usuário. | Preferir token Bearer enviado explicitamente. Se usar cookies, habilitar proteção CSRF e atributos `Secure`, `HttpOnly` e `SameSite`. | Baixo |
| Todos os endpoints (disponibilidade) | Excesso de requisições, payloads grandes e paginação sem limite. | Indisponibilidade ou degradação do serviço. | Limites de tamanho de payload e de itens por página; rate limiting no login; timeouts; monitoramento. | Médio |
| Respostas e logs | Vazamento de tokens, senhas, dados internos ou stack traces. | Comprometimento de contas e exposição de informações. | Não registrar segredos; erros padronizados; não expor detalhes internos; restringir acesso aos logs. | Médio |
| Banco e configurações | Credenciais expostas ou privilégios excessivos. | Vazamento, alteração ou perda dos dados. | Privilégio mínimo no banco; segredos fora do código/Git; variáveis de ambiente ou cofre; backups protegidos. | Alto |
| Documentação, monitoramento e dependências | Swagger, Actuator ou console do banco expostos em produção; bibliotecas com vulnerabilidades conhecidas. | Revelação de estrutura interna e exploração de falhas conhecidas. | Desativar ou proteger esses recursos em produção; perfis separados (desenvolvimento/produção); cabeçalhos de segurança; atualizar e verificar dependências periodicamente. | Médio |

---

## 3. Plano de Segurança da API

### 3.1 Autenticação

O usuário fará login com e-mail e senha em `POST /auth/login`. Após a validação, a API retornará um token JWT assinado. Nas requisições protegidas, o cliente enviará `Authorization: Bearer <token>`, e a API validará assinatura, algoritmo e expiração a cada requisição. Toda a comunicação utilizará HTTPS.

As senhas serão armazenadas somente como hash seguro, com BCrypt ou Argon2, e será exigido um tamanho mínimo de senha. Senhas e tokens não serão incluídos em respostas ou logs. Haverá limite de tentativas de login, com bloqueio temporário, e a mesma mensagem genérica será usada para usuário inexistente e senha incorreta.

O token terá expiração curta, definida em configuração, e conterá apenas o identificador e o perfil do usuário. A chave de assinatura será forte e mantida fora do código. Na primeira versão, o logout poderá ser feito descartando o token no cliente; refresh token e revogação no servidor ficam como evolução futura.

### 3.2 Recursos públicos e protegidos

| Tipo de acesso | Operações |
|---|---|
| Público | `POST /auth/login`. Na primeira versão, não haverá consulta pública de estoque ou cadastros. |
| Protegido | Todos os demais endpoints. O acesso dependerá do perfil e das permissões definidas na [seção 4](#4-perfis-e-permissões). Documentação da API e endpoints de monitoramento não ficarão abertos em produção. |

### 3.3 Autorização

Será adotado controle de acesso baseado em papéis (RBAC), seguindo o princípio do menor privilégio. As regras serão aplicadas no backend, e não somente na interface, e o acesso será negado por padrão a tudo que não for explicitamente permitido. O operador poderá executar as atividades rotineiras do estoque; operações administrativas de cadastro, exclusão, configuração e gestão de usuários ficarão restritas ao administrador. Requisições sem autenticação receberão 401, e requisições sem permissão, 403.

### 3.4 Validação e integridade

A API validará obrigatoriedade, tipo, formato, tamanho e limites dos dados e aceitará apenas os campos previstos em cada DTO de entrada. IDs serão positivos; a quantidade de movimentação será maior que zero; o estoque mínimo não poderá ser negativo; datas e filtros deverão ser coerentes. O acesso ao banco usará ORM ou consultas parametrizadas, sem concatenar entradas em comandos SQL.

A gravação da movimentação e a atualização do saldo ocorrerão de forma transacional, com controle de concorrência, e uma saída não poderá deixar o estoque negativo. As movimentações não serão editadas nem excluídas: correções serão feitas por lançamento de ajuste ou estorno. Pastilhas, fabricantes e fornecedores com vínculos não poderão ser excluídos.

### 3.5 CORS e CSRF

O CORS permitirá somente a origem autorizada do frontend, configurada por ambiente, e liberará apenas os métodos e cabeçalhos necessários, como `Authorization` e `Content-Type`. Não será usado `Access-Control-Allow-Origin: *` com credenciais.

Com o token Bearer enviado explicitamente no cabeçalho, o risco de CSRF é reduzido, pois o navegador não adiciona esse cabeçalho automaticamente em requisições de outros sites. Se forem adotados cookies de autenticação, será necessária proteção CSRF e configuração segura dos cookies (`Secure`, `HttpOnly` e `SameSite`).

### 3.6 XSS e tratamento de erros

Dados recebidos serão tratados como conteúdo, nunca como código. A interface deverá escapar os valores exibidos e evitar interpretar conteúdo cadastrado como HTML. As respostas de erro seguirão um formato padronizado e não apresentarão SQL, stack traces ou detalhes internos.

### 3.7 Auditoria e logs

Serão registrados eventos relevantes: logins (com sucesso e com falha), acessos negados, alterações de cadastros, movimentações, mudanças de estoque mínimo e gestão de usuários. Cada registro conterá data/hora, usuário, ação, recurso e resultado, sem senhas, tokens ou outros segredos. O acesso aos logs será restrito.

### 3.8 Disponibilidade

A API terá limite de tamanho de requisição, paginação com tamanho máximo de página, limite de período nas consultas de histórico e relatórios, timeouts e limitação de tentativas no login. O comportamento da aplicação deverá ser monitorado.

### 3.9 Banco de dados e segredos

A aplicação utilizará uma conta de banco com os privilégios mínimos necessários. Credenciais e segredos, incluindo a chave de assinatura do JWT, não serão versionados no Git nem inseridos no código; serão fornecidos por variáveis de ambiente ou mecanismo seguro equivalente. Backups terão acesso restrito e proteção adequada.

### 3.10 Configuração e dependências

Os ambientes de desenvolvimento e produção terão configurações separadas. Em produção, recursos como documentação interativa, endpoints de monitoramento e console do banco ficarão desativados ou protegidos, e serão enviados cabeçalhos de segurança. As dependências do projeto serão mantidas atualizadas e verificadas periodicamente quanto a vulnerabilidades conhecidas.

---

## 4. Perfis e Permissões

| Recurso/operação | Público | Operador | Administrador |
|---|:---:|:---:|:---:|
| Realizar login | Sim | Sim | Sim |
| Consultar pastilhas | Não | Sim | Sim |
| Cadastrar/alterar/excluir pastilhas | Não | Não | Sim |
| Consultar fabricantes | Não | Sim | Sim |
| Cadastrar/alterar/excluir fabricantes | Não | Não | Sim |
| Consultar fornecedores | Não | Sim | Sim |
| Cadastrar/alterar/excluir fornecedores | Não | Não | Sim |
| Consultar estoque atual e crítico | Não | Sim | Sim |
| Definir estoque mínimo | Não | Não | Sim |
| Registrar entrada | Não | Sim | Sim |
| Registrar saída | Não | Sim | Sim |
| Registrar ajuste/estorno de movimentação | Não | Não | Sim |
| Consultar histórico de movimentações | Não | Sim | Sim |
| Consultar relatórios | Não | Operacionais | Todos |
| Gerenciar usuários e perfis | Não | Não | Sim |

- **Público:** pessoa não autenticada, com acesso somente ao login.
- **Operador:** usuário autenticado que consulta o estoque e registra movimentações.
- **Administrador:** usuário com permissões de gerenciamento, o único que atribui perfis.

> **Relatórios operacionais (proposta):** estoque atual e crítico e histórico de movimentações por período. Os demais relatórios ficam restritos ao administrador; a divisão final deve ser confirmada com a DDA Metalúrgica. O gerenciamento de usuários é uma permissão planejada; endpoints específicos deverão ser incluídos no contrato caso essa função faça parte da primeira versão.

---

## 5. Respostas HTTP relacionadas à segurança

| Código | Uso previsto |
|---|---|
| `200 OK` | Consulta ou atualização concluída. |
| `201 Created` | Recurso ou movimentação criado. |
| `204 No Content` | Exclusão concluída sem corpo de resposta. |
| `400 Bad Request` | Requisição inválida ou dados fora das regras (ex.: quantidade menor ou igual a zero). |
| `401 Unauthorized` | Credenciais ausentes ou inválidas, ou token inválido/expirado. |
| `403 Forbidden` | Usuário autenticado sem permissão para a operação. |
| `404 Not Found` | Recurso não encontrado. |
| `409 Conflict` | Conflito de regra de negócio, como código duplicado, exclusão de registro vinculado ou estoque insuficiente. |
| `413 Payload Too Large` | Corpo da requisição acima do limite permitido. |
| `429 Too Many Requests` | Limite de requisições ou de tentativas de login excedido. |
| `500 Internal Server Error` | Erro inesperado, com mensagem genérica e sem detalhes internos. |

---

## 6. Testes de segurança previstos

Os cenários abaixo deverão ser executados na implementação, preferencialmente de forma automatizada, e servem como critério de aceite das medidas descritas.

| Cenário de teste | Resultado esperado |
|---|---|
| Login com senha incorreta e com e-mail inexistente | Mesma resposta genérica (401), sem indicar qual dado falhou. |
| Várias tentativas de login seguidas | Bloqueio temporário e resposta 429. |
| Endpoint protegido sem token, com token expirado ou com assinatura alterada | Resposta 401. |
| Operador tentando cadastrar, alterar ou excluir pastilhas, alterar estoque mínimo ou gerenciar usuários | Resposta 403. |
| Operador e administrador executando as operações permitidas ao seu perfil | Sucesso (200, 201 ou 204). |
| Movimentação com quantidade zero, negativa ou tipo inválido | Resposta 400. |
| Saída maior que o saldo disponível | Resposta 409 e saldo inalterado. |
| Duas saídas simultâneas sobre o mesmo saldo | Saldo nunca fica negativo; apenas a saída que couber no saldo é aceita. |
| Exclusão de pastilha, fabricante ou fornecedor com vínculos | Resposta 409 e registro preservado. |
| Campos com texto típico de SQL Injection e de HTML/script | Tratados como texto: banco inalterado e nenhum script executado na interface. |
| Requisição de origem não autorizada (CORS) | Bloqueada pelo navegador, sem cabeçalhos CORS permissivos. |
| Listagem sem paginação ou com tamanho de página excessivo | Limite máximo aplicado. |
| Erro interno forçado | Resposta 500 genérica, sem stack trace ou SQL. |
| Inspeção de respostas e logs | Nenhuma senha, token ou segredo registrado ou retornado. |

---

## 7. Considerações finais

Este documento representa o planejamento inicial de segurança da API. Na implementação com Spring Security, as regras de autenticação, autorização, CORS, validação, registro e monitoramento deverão ser configuradas e testadas, e a matriz deverá ser revisada sempre que novos endpoints ou perfis forem incluídos.

**Pontos a definir com a DDA Metalúrgica:**

- tempo de expiração do token e número de tentativas de login antes do bloqueio;
- quais relatórios serão liberados ao operador;
- se o gerenciamento de usuários fará parte da primeira versão.

**Referências de apoio:** OWASP API Security Top 10 (2023), OWASP ASVS e a documentação oficial do Spring Security.
