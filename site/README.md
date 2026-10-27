# Ordens de Compra de gado (GVQ)

Site para solicitar, analisar e acompanhar Ordens de Compra de compra e transferência de gado, com login próprio e dois perfis:

- **Solicitante**: vê só "Nova solicitação" e "Minhas solicitações".
- **Analista**: vê tudo e também gera OCs, aprova viabilidade, edita cadastros e cria usuários.

As permissões são verificadas no servidor, não só na tela: um solicitante não consegue ler OCs nem mexer em pedidos de outras pessoas, mesmo tentando pela API.

## O que vem pronto

- As 552 OCs da planilha (117 em andamento e 435 fechadas). A próxima OC gerada é a 1652.
- Os cadastros de raças, responsáveis, fazendas de destino, outras fazendas, origens de compra e proprietários.
- Dois usuários de teste, ambos com a senha inicial `12345`:
  - `matheus.souza`, analista
  - `matheus.silveira`, solicitante

No primeiro login o sistema obriga a trocar a senha inicial por outra com pelo menos 8 caracteres.

## Rodar no computador (teste)

Precisa do Node.js 20 ou mais novo.

```bash
npm install
npm run seed      # cria o banco com os dados acima (pode rodar de novo sem duplicar nada)
npm start         # abre em http://localhost:3000
```

## Colocar no ar (para a TI)

É um único servidor Node.js com banco SQLite em arquivo (`dados/ocs.sqlite`). Pontos obrigatórios:

1. **HTTPS.** Rode atrás de um proxy com certificado (Nginx, Caddy, IIS ou o próprio serviço de hospedagem) e defina `NODE_ENV=production`, que ativa o cookie seguro.
2. **Disco persistente** para a pasta `dados/`. Sem ele as solicitações se perdem a cada reinício.
3. **Backup diário** do arquivo `dados/ocs.sqlite`.

Com Docker:

```bash
docker build -t gvq-ocs .
docker run -d -p 3000:3000 -v gvq-ocs-dados:/app/dados --name gvq-ocs gvq-ocs
```

Variáveis de ambiente:

| Variável | Padrão | Para quê |
|---|---|---|
| `PORT` | `3000` | Porta do servidor |
| `NODE_ENV` | (vazio) | Use `production` no servidor |
| `BANCO` | `dados/ocs.sqlite` | Caminho do arquivo do banco |
| `SESSAO_HORAS` | `12` | Tempo até pedir login de novo |

## Segurança

- Senhas guardadas com bcrypt. Ninguém, nem o analista, consegue ver a senha de outra pessoa; o analista só pode redefinir.
- Sessão em cookie `HttpOnly` e `SameSite=Strict`; desativar um usuário ou redefinir a senha encerra as sessões dele.
- Após 8 tentativas erradas, o login daquele usuário fica bloqueado por 15 minutos.
- Troque as senhas de teste antes de liberar para todos e desative os usuários de teste quando não forem mais necessários.

## Estrutura

```
server.js            API e regras de permissão
db.js                Tabelas do banco
seed.js              Carga inicial (cadastros, OCs da planilha, usuários de teste)
dados-iniciais/      Cadastros e OCs importados das planilhas
public/index.html    Telas (login, formulário, análise, OCs, cadastros, usuários)
```
