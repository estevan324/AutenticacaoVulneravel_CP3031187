# OWASP API Security Top 10: O Checklist Completo de Testes (2026)

**Autora:** Likhitha Venkata | **Editado em:** 16 de março de 2026

---

## Por que você precisa de um checklist dedicado de conformidade com OWASP API

O OWASP API Top 10 é cada vez mais referenciado por auditores de PCI-DSS, HIPAA, GDPR e DORA. É um framework com o qual você precisa demonstrar conformidade repetidamente, com evidências.

Este checklist é agnóstico de ferramenta por design. Ele diz o que deve ser testado, quais evidências são necessárias para demonstrar conformidade e em qual estágio do ciclo de vida da API cada verificação se encaixa: design, pré-produção ou tempo real (runtime). Use-o como modelo para auditoria interna, como gate de segurança para desenvolvedores, como framework de revisão trimestral de postura ou como ponto de partida para mapear segurança de API com obrigações regulatórias mais amplas.

Ele cobre o OWASP API Security Top 10 (edição 2023), a referência oficial atual. Cada seção inclui: a definição do risco, a pergunta de conformidade que você deve responder, testes específicos a serem executados e evidências a serem coletadas.

**Não consegue abordar todos os 10 de uma vez?** Estes três impulsionam a maioria das violações reais de API:

- **API1 – BOLA**
- **API2 – Broken Auth**
- **API9 – Inventory**

Depois, avance para: API3, API5, API8. Finalize com API6, API7, API10 com base na sua arquitetura.

---

## Como usar este checklist

Cada risco da OWASP API é mapeado em três dimensões do checklist:

| Dimensão | O que significa |
|----------|----------------|
| Cobertura de testes | Quais cenários devem ser exercitados para reivindicar cobertura |
| Padrão de evidência | Qual artefato prova que o teste foi executado e que o controle se mantém |
| Posição no ciclo de vida | Tempo de design, pré-produção (CI/CD), tempo real (runtime) ou todos os três |

Uma **aprovação** requer evidência no estágio apropriado do ciclo de vida. Logs de gateway e alertas de WAF sozinhos não são evidência suficiente para a maioria das reivindicações de conformidade com OWASP API; eles capturam apenas o que o perímetro vê, não o que os serviços internos expõem ou como a autorização se comporta entre tipos de objeto.

---

## API1: Broken Object Level Authorization (BOLA)

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Um usuário logado altera um ID em uma requisição (ex.: `/orders/1234` → `/orders/1235`) e obtém dados de outra pessoa. A API nunca verifica se ele é o proprietário daquele objeto.

### O QUE TESTAR

- Use o token do Usuário A para solicitar objetos pertencentes ao Usuário B — espere um `403` ou `404`, não um `200`.
- Teste cada tipo de objeto: pedidos, documentos, transações, configurações — não apenas perfis de usuário.
- Verifique escalada vertical: um usuário comum consegue acessar objetos de nível admin?
- Em aplicações multi-tenant, o Tenant A consegue acessar dados do Tenant B?
- Confirme que a autorização acontece no lado do servidor, não baseada em parâmetros enviados pelo cliente.

### EVIDÊNCIAS NECESSÁRIAS

- Pares de requisição/resposta mostrando que o acesso entre usuários foi bloqueado.
- Uma matriz mapeando cada tipo de objeto para um teste de autorização.
- Logs de auditoria do lado do servidor das decisões de negação (não apenas logs de gateway).

---

## API2: Broken Authentication

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Autenticação fraca ou falha permite que atacantes roubem tokens, forcem credenciais ou ignorem o login completamente, incluindo truques com JWT ou configurações incorretas de OAuth.

### O QUE TESTAR

- Confirme que cada endpoint exige autenticação — endpoints antigos, internos e de admin.
- Teste falhas de JWT: bypass `alg:none`, confusão de algoritmo, força bruta de chave fraca.
- Verifique que os tokens expiram após logout e após seu TTL.
- Teste OAuth: validação de URI de redirecionamento, PKCE para clientes públicos, parâmetro `state` anti-CSRF.
- Confirme rate limiting e bloqueio em endpoints de login (proteção contra credential stuffing).
- Verifique que erros de autenticação são genéricos, sem enumeração de usuário via mensagens de erro diferentes.

### EVIDÊNCIAS NECESSÁRIAS

- Relatório de teste de penetração cobrindo validação de token e resistência a ataques de credenciais.
- Capturas de tela de configuração mostrando TTL de token, rotação e revogação.
- Logs de rate limiting em endpoints de login sob ataque simulado.

---

## API3: Broken Object Property Level Authorization

**Ciclo de vida:** Design | Pré-produção

**O que significa:** APIs expõem campos que os usuários não deveriam ver (ex.: IDs internos, PII de outros usuários), ou aceitam escritas em campos que não deveriam controlar (ex.: enviar `role: admin` em uma requisição de cadastro).

### O QUE TESTAR

- Verifique cada resposta da API: campos sensíveis (PII, credenciais, dados financeiros) são filtrados por papel?
- Teste de mass assignment: envie `isAdmin: true`, `balance: 9999` em POST/PATCH — eles devem ser ignorados.
- Verifique que campos somente leitura não podem ser alterados através de nenhum endpoint de escrita.
- Para GraphQL: teste introspecção, autorização em nível de campo e limites de profundidade de query.

### EVIDÊNCIAS NECESSÁRIAS

- Diff de respostas mostrando diferentes campos retornados por papel.
- Resultados de testes de mass assignment (pares requisição/resposta).
- Auditoria de esquema confirmando que a documentação corresponde ao que a API realmente retorna.

---

## API4: Unrestricted Resource Consumption

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Sem limites de taxa, sem limites de tamanho de payload e sem limites de complexidade de consulta, abrindo portas para negação de serviço, custos excessivos de nuvem ou enumeração por força bruta.

### O QUE TESTAR

- Rate limiting aplicado por usuário, por IP e por chave de API em todos os endpoints críticos.
- Tente contornar rate limits: falsifique `X-Forwarded-For`, distribua requisições entre IPs, ataques de taxa lenta.
- Corpos de requisição excessivamente grandes devem ser rejeitados em todos os endpoints POST/PUT/PATCH.
- Endpoints de listagem devem limitar o parâmetro `limit` — sem consultas ilimitadas.
- GraphQL: imponha limites de profundidade, complexidade e contagem de campos.

### EVIDÊNCIAS NECESSÁRIAS

- Exportações de configuração de rate limit ou definições de política como código.
- Resultados de testes de carga mostrando que os limites se mantêm nos limiares definidos.
- Amostras de log mostrando respostas `429` com cabeçalhos `Retry-After`.

---

## API5: Broken Function Level Authorization

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Usuários comuns podem chamar funções de nível administrativo diretamente — gestão de usuários, exclusões em massa, alterações de configuração — simplesmente sabendo a URL do endpoint.

### O QUE TESTAR

- Mapeie cada endpoint e atribua um nível de privilégio necessário — incluindo os não documentados.
- Chame cada endpoint privilegiado usando um token de usuário comum.
- Teste substituição de método HTTP: se GET está protegido, tente POST/DELETE no mesmo caminho.
- Verifique bypass via parâmetros: `?admin=true`, `?role=admin`.
- Endpoints internos como `/actuator`, `/metrics`, `/admin` devem ser bloqueados ou não expostos.
- Versões antigas da API devem aplicar os mesmos controles de acesso que as atuais.

### EVIDÊNCIAS NECESSÁRIAS

- Inventário completo de endpoints com classificação de privilégio.
- Resultados de teste de penetração cobrindo proteção de endpoints privilegiados.
- Documentação de política de controle de acesso por categoria de função.

---

## API6: Unrestricted Access to Sensitive Business Flows

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Fluxos críticos — checkout, validação de OTP, resgate de promoções e criação de contas — podem ser scriptados e abusados em escala sem salvaguardas além de limites de taxa básicos.

### O QUE TESTAR

- Cada fluxo crítico pode ser scriptado e repetido em escala sem acionar um bloqueio?
- Endpoints de OTP/verificação: limites de tentativas, expiração e invalidação de uso único são aplicados?
- Fluxos de múltiplas etapas: você pode pular uma etapa e ir direto ao final (ex.: pular pagamento)?
- Endpoints de voucher/promoção: um único usuário consegue enumerar e resgatar códigos em escala?
- Condições de corrida: teste requisições concorrentes no mesmo recurso (gasto duplo, cupons duplicados).

### EVIDÊNCIAS NECESSÁRIAS

- Inventário de fluxos de negócio com cenários de abuso documentados.
- Resultados de testes de automação mostrando que os controles se mantêm sob carga scriptada.
- Resultados de validação de sequência confirmando a aplicação da ordem das etapas.

---

## API7: Server-Side Request Forgery (SSRF)

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** A API busca uma URL fornecida pelo usuário e um atacante a aponta para serviços internos, endpoints de metadados de nuvem (169.254.169.254) ou faixas de IP internas.

### O QUE TESTAR

- Encontre cada parâmetro que aceita URL, caminho de arquivo, hostname ou destino de webhook.
- Teste alvos internos: `127.0.0.1`, `10.x.x.x`, `169.254.169.254` (metadados de nuvem).
- Teste esquemas não HTTP: `file://`, `gopher://`, `ftp://` — todos devem ser rejeitados.
- SSRF cego: use callbacks DNS para detectar buscas que não aparecem nas respostas.
- URLs de webhook/callback: valide apenas contra uma lista de permissões explícita.

### EVIDÊNCIAS NECESSÁRIAS

- Inventário de todos os parâmetros que aceitam URL.
- Resultados de testes SSRF com requisições bloqueadas para alvos internos documentadas.
- Configuração da lista de permissões de webhook/callback.

---

## API8: Security Misconfiguration

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** Mensagens de erro verbosas, CORS permissivo, endpoints de debug expostos, cabeçalhos de segurança ausentes ou TLS fraco — configurações incorretas simples que entregam vitórias fáceis aos atacantes.

### O QUE TESTAR

- TLS 1.0/1.1 desabilitado; TLS 1.2+ forçado com cipher suites fortes.
- Cabeçalhos de segurança presentes em todas as respostas: HSTS, `X-Content-Type-Options`, CSP.
- CORS: sem `*` curinga em endpoints autenticados — origens devem estar em lista de permissões.
- Respostas de erro: sem stack traces, caminhos internos ou erros de BD em produção.
- Endpoints de debug/gerenciamento desabilitados em produção: `/swagger-ui`, `/actuator`, `/env`.
- Credenciais padrão e chaves de API de exemplo removidas de todos os ambientes.

### EVIDÊNCIAS NECESSÁRIAS

- Relatório de varredura de cabeçalhos de segurança.
- Exportação de configuração TLS ou saída de varredura.
- Lista confirmada de endpoints de debug desabilitados em produção.

---

## API9: Improper Inventory Management

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** APIs que ninguém lembra que implantou — versões antigas, serviços sombra, endpoints internos esquecidos — existem com controles de segurança mais fracos (ou nenhum) e passam despercebidas.

### O QUE TESTAR

- Mantenha um inventário autoritativo: endpoint, versão, requisitos de autenticação, classificação de dados, proprietário.
- Execute descoberta contínua para detectar endpoints que não estão no inventário.
- Inventarie tráfego leste-oeste (serviço interno para serviço interno) — não apenas APIs públicas.
- Todas as versões descontinuadas que ainda recebem tráfego devem ter um cronograma de desativação documentado.
- Versões antigas da API devem aplicar os mesmos controles de autenticação que as atuais — sem controles mais fracos.

### EVIDÊNCIAS NECESSÁRIAS

- Exportação do inventário de API com campos de versão e propriedade preenchidos.
- Relatório delta de varredura de descoberta (inventário vs. o que está realmente rodando).
- Política de descontinuação com datas de aplicação.

---

## API10: Unsafe Consumption of APIs

**Ciclo de vida:** Design | Pré-produção | Runtime

**O que significa:** A aplicação confia cegamente nas respostas de processadores de pagamento, provedores de identidade ou serviços de enriquecimento de dados — uma API upstream comprometida pode injetar dados maliciosos diretamente em seu sistema.

### O QUE TESTAR

- Liste cada API de terceiros que sua aplicação consome e documente o fluxo de dados.
- Valide todas as respostas de terceiros contra um esquema esperado antes de processar.
- Sanitize dados de terceiros para injeção (SQL, comando, HTML) antes de armazenar ou usar.
- Valide certificados TLS em todas as conexões de API de saída — rejeite certificados inválidos ou expirados.
- Teste o que acontece com um esquema inesperado ou resposta malformada — a aplicação deve degradar graciosamente.
- Chaves de API e tokens OAuth para serviços de terceiros devem estar em um gerenciador de segredos, não no código.

### EVIDÊNCIAS NECESSÁRIAS

- Inventário de APIs de terceiros com documentação de fluxo de dados.
- Resultados de testes de validação de esquema para tratamento de respostas de terceiros.
- Configuração de gerenciamento de segredos para todas as credenciais de API externas.

---

## Matriz de Evidências de Conformidade (Melhor para Documentos de Segurança)

| Categoria de Evidência | O que deve ser produzido | Exemplo de Artefato | Por que é importante |
|------------------------|--------------------------|---------------------|----------------------|
| Registros de Execução de Testes | Logs com timestamp dos testes de API | Logs de requisição/resposta, saída de varredura | Prova que o controle foi realmente testado |
| Documentação de Cobertura | Mapeamento de APIs para cenários OWASP | Relatório de cobertura de endpoints | Mostra testes em todas as versões de API e endpoints internos |
| Registros de Remediação | Documentação da correção + novo teste | Ticket no rastreador de issues + varredura de validação | Demonstra o fechamento da vulnerabilidade |
| Evidência Contínua | Dados de monitoramento contínuo | Telemetria de runtime, dashboards de segurança | Prova que o controle funciona ao longo do tempo |

---

## Resumo do Ciclo de Vida do Checklist

| Risco OWASP | Design | Pré-produção | Runtime |
|-------------|--------|--------------|---------|
| API1: BOLA | Definir requisitos de autorização de objeto | Teste dinâmico de controle de acesso | Análise comportamental |
| API2: Broken Auth | Revisão do esquema de autenticação | Teste de fluxo de autenticação | Detecção de anomalias |
| API3: Property Auth | Definições de esquema e papéis | Teste de resposta baseado em papel | Monitoramento de exposição de dados |
| API4: Resource Limits | Definição da política de rate limit | Teste de carga e abuso | Monitoramento de consumo |
| API5: Function Auth | Taxonomia de privilégios | Teste de endpoints privilegiados | Detecção de anomalias |
| API6: Business Flows | Modelagem de cenários de abuso | Teste de automação e sequência | Análise comportamental |
| API7: SSRF | Política de tratamento de entrada | Teste dinâmico focado em SSRF | Monitoramento de egresso |
| API8: Misconfiguration | Baseline de configuração | Varredura de configuração incorreta | Detecção de desvios |
| API9: Inventory | Registro no inventário | Análise de lacunas de cobertura | Descoberta contínua |
| API10: Third-Party APIs | Avaliação de risco de terceiros | Teste de integração | Monitoramento de saída |

---

## Falhas Comuns no Checklist (E Como Evitá-las)

- ❌ **Apenas testar APIs visíveis ao gateway.** OWASP API9 e dados reais de violações deixam claro que o tráfego interno (leste-oeste) é uma superfície de ataque primária. Seu checklist deve cobrir explicitamente fluxos leste-oeste, não apenas endpoints publicamente roteáveis.

- ❌ **Usar resultados de varreduras genéricas como evidência de BOLA ou BFLA.** Falhas de API1 e API5 são problemas de lógica de negócio. Scanners automatizados sem modelagem realista de autenticação e objetos produzem falsos negativos. A evidência requer testes que realmente usem tokens válidos em diferentes contextos de usuário.

- ❌ **Tratar a cobertura da versão 1 como cobrindo todas as versões.** API9 explicitamente menciona versionamento não gerenciado. Seu checklist deve cobrir todas as versões de API implantadas, incluindo versões legadas ou descontinuadas que ainda recebem tráfego.

- ❌ **Varreduras pontuais para riscos de runtime.** Desvios de autorização, novos endpoints sombra e padrões de abuso comportamentais não podem ser provados com snapshots periódicos. Controles de runtime exigem evidência contínua, não registros de teste anuais.

- ❌ **Cobertura de esquema sem validação de runtime.** Verificações baseadas em contrato capturam o que a especificação diz. Elas não capturam o que a API implantada realmente faz sob condições reais de autenticação. Ambas as camadas são necessárias para evidência de conformidade crível.

---

## Usando Este Checklist na Prática

✅ **Para auditorias internas:** Execute cada seção trimestralmente. Atribua a propriedade de cada risco OWASP a uma equipe ou indivíduo. Use os requisitos de evidência para definir como é uma constatação de auditoria "fechada" antes de começar.

✅ **Para gates de segurança de desenvolvedores:** Extraia os itens do checklist de pré-produção e converta-os em critérios de aceitação CI/CD. Uma build que não passou nas verificações de BOLA, autenticação quebrada e configuração incorreta contra um ambiente de staging não deve prosseguir para produção sem uma exceção documentada.

✅ **Para submissões regulatórias:** Use a tabela de referência cruzada do framework para mapear seus artefatos de evidência OWASP para o controle regulatório específico que eles satisfazem. Auditores aceitam cada vez mais evidências de conformidade com OWASP API como documentação de suporte para PCI-DSS 6.x e salvaguardas técnicas da HIPAA.

✅ **Para postura contínua:** Use a coluna "Runtime" como um checklist de design de monitoramento. Cada item representa um sinal que sua camada de runtime deve estar produzindo e roteando para SIEM ou para uma equipe de operações.

---

## Hub de Recursos de Segurança de API da AccuKnox

Explore a base de conhecimento completa de segurança de API da AccuKnox:

- **API Security Posture Management** – Como a AccuKnox estende o CNAPP para o gerenciamento completo do ciclo de vida da API.
- **10 Melhores Ferramentas de Segurança de API em 2026** – Comparação abrangente de ferramentas de runtime e teste.
- **API Discovery & Visibility** – Como a AccuKnox usa eBPF para encontrar todos os endpoints de API.
- **Documentos de Ajuda de Segurança de API**

---

## FAQ

**Este checklist é suficiente para uma auditoria de segurança de API PCI-DSS?**

Ele cobre os requisitos de teste técnico que mapeiam para PCI-DSS 6.2 e 6.4 para APIs, mas a conformidade com PCI-DSS também requer controles de processo, treinamento e artefatos de governança além dos testes técnicos. Use este checklist como a camada técnica de um programa de conformidade mais amplo.

**Com que frequência devo executar o checklist completo?**

As verificações de pré-produção devem ser executadas com cada mudança significativa na API. O checklist completo — incluindo a validação de postura em runtime — deve ser revisado pelo menos trimestralmente, ou após qualquer mudança significativa na infraestrutura, evento de versionamento de API ou atualização de integração de terceiros.

**Preciso testar o tráfego leste-oeste (serviço interno para serviço interno) separadamente?**

Sim. Chamadas de API leste-oeste representam a maioria do tráfego de API em ambientes de microsserviços e são o caminho primário para movimento lateral em violações relacionadas a API. Seu inventário (API9) e evidência de controle de acesso (API1, API5) devem incluir explicitamente cobertura leste-oeste para serem críveis.

**Qual é o stack de teste mínimo viável para cobrir todos os 10 riscos?**

No mínimo: uma ferramenta de teste dinâmico com modelagem realista de autenticação (para API1–API7), uma etapa de varredura de configuração (para API8), um mecanismo de inventário/descoberta (para API9) e um processo de revisão de integração de API de terceiros (para API10). A visibilidade em runtime deve ser adicionada como camada superior para evidência contínua.

**Como priorizar se não posso cobrir todos os 10 riscos de uma vez?**

Comece com **API1 (BOLA)**, **API2 (Broken Auth)** e **API9 (Inventory)**. Estes três impulsionam a maioria das violações reais de API e são as lacunas mais comumente citadas em auditorias de segurança de API. Uma vez cobertos, adicione API3, API5 e API8. API6, API7 e API10 vêm em seguida, com base no seu modelo de negócios específico e no perfil de dependência de terceiros.

---

## Pronto para uma Avaliação de Segurança Personalizada?

**Agende uma demonstração ao vivo** com a AccuKnox e veja como automatizar a conformidade com OWASP API Security Top 10.

---

© Copyright 2026 AccuKnox – todos os direitos reservados.  
[Termos de Uso] | [Política de Privacidade] | [Acordo de Avaliação] | [SLA]