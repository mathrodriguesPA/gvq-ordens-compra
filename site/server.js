// Sistema de Ordens de Compra de gado (GVQ)
// Servidor único: Express + SQLite. Login por usuário e senha, perfis Analista e Solicitante.
'use strict';
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { abrirBanco } = require('./db');

const PORT = Number(process.env.PORT) || 3000;
const PRODUCAO = process.env.NODE_ENV === 'production';
const SESSAO_HORAS = Number(process.env.SESSAO_HORAS) || 12;
const db = abrirBanco();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Cabeçalhos de segurança básicos
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'");
  next();
});

/* ---------------- utilidades ---------------- */
const agora = () => new Date().toISOString();
const novoId = () => crypto.randomBytes(9).toString('base64url');
const json = v => JSON.stringify(v);
const parse = s => { try { return JSON.parse(s); } catch { return null; } };
const chave = s => String(s || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/^faz\.?\s*/, '').replace(/[^a-z0-9]/g, '');
const unicos = arr => { const vistos = new Set(); return arr.filter(v => { const k = chave(v); if (!k || vistos.has(k)) return false; vistos.add(k); return true; }).sort((a, b) => a.localeCompare(b, 'pt-BR')); };
const texto = (v, max = 300) => (v == null ? '' : String(v)).trim().slice(0, max);
const erro = (res, status, mensagem) => res.status(status).json({ erro: mensagem });

function lerCookie(req, nome) {
  const c = req.headers.cookie || '';
  for (const parte of c.split(';')) {
    const [k, ...v] = parte.trim().split('=');
    if (k === nome) return decodeURIComponent(v.join('='));
  }
  return null;
}
function gravarCookie(res, valor, maxAgeSeg) {
  const partes = [`sessao=${encodeURIComponent(valor)}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSeg}`];
  if (PRODUCAO) partes.push('Secure');
  res.setHeader('Set-Cookie', partes.join('; '));
}
const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');

/* ---------------- sessão e permissões ---------------- */
function autenticar(req, res, next) {
  const token = lerCookie(req, 'sessao');
  if (!token) return erro(res, 401, 'Faça login para continuar.');
  const s = db.prepare(`SELECT s.expira_em, u.id, u.usuario, u.nome, u.perfil, u.ativo, u.trocar_senha
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token_hash = ?`).get(hashToken(token));
  if (!s || s.expira_em < agora() || !s.ativo) {
    if (s) db.prepare('DELETE FROM sessoes WHERE token_hash = ?').run(hashToken(token));
    return erro(res, 401, 'Sua sessão expirou. Entre de novo.');
  }
  req.usuario = { id: s.id, usuario: s.usuario, nome: s.nome, perfil: s.perfil, trocarSenha: !!s.trocar_senha };
  next();
}
const somenteAnalista = (req, res, next) => req.usuario.perfil === 'analista' ? next() : erro(res, 403, 'Apenas analistas podem fazer isso.');
// Protege contra envio de formulário de outro site: toda alteração precisa ser JSON
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method) && !req.is('application/json')) return erro(res, 415, 'Envie os dados em JSON.');
  next();
});

/* ---------------- login ---------------- */
const tentativas = new Map(); // limite simples: 8 erros em 15 min por usuário+IP
function bloqueado(k) { const t = tentativas.get(k); return t && t.n >= 8 && Date.now() - t.ini < 15 * 60e3; }
function falhou(k) { const t = tentativas.get(k); if (!t || Date.now() - t.ini > 15 * 60e3) tentativas.set(k, { n: 1, ini: Date.now() }); else t.n++; }

app.post('/api/login', (req, res) => {
  const usuario = texto(req.body.usuario, 80).toLowerCase();
  const senha = String(req.body.senha || '');
  const k = usuario + '|' + req.ip;
  if (bloqueado(k)) return erro(res, 429, 'Muitas tentativas. Espere 15 minutos e tente de novo.');
  const u = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario);
  if (!u || !u.ativo || !bcrypt.compareSync(senha, u.senha_hash)) { falhou(k); return erro(res, 401, 'Usuário ou senha incorretos.'); }
  tentativas.delete(k);
  const token = crypto.randomBytes(32).toString('base64url');
  const expira = new Date(Date.now() + SESSAO_HORAS * 3600e3).toISOString();
  db.prepare('INSERT INTO sessoes (token_hash, usuario_id, criado_em, expira_em) VALUES (?,?,?,?)').run(hashToken(token), u.id, agora(), expira);
  db.prepare('DELETE FROM sessoes WHERE expira_em < ?').run(agora());
  gravarCookie(res, token, SESSAO_HORAS * 3600);
  res.json({ id: u.id, usuario: u.usuario, nome: u.nome, perfil: u.perfil, trocarSenha: !!u.trocar_senha });
});

app.post('/api/logout', (req, res) => {
  const token = lerCookie(req, 'sessao');
  if (token) db.prepare('DELETE FROM sessoes WHERE token_hash = ?').run(hashToken(token));
  gravarCookie(res, '', 0);
  res.json({ ok: true });
});

app.get('/api/eu', autenticar, (req, res) => res.json(req.usuario));

app.post('/api/senha', autenticar, (req, res) => {
  const { atual, nova } = req.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.usuario.id);
  if (!bcrypt.compareSync(String(atual || ''), u.senha_hash)) return erro(res, 400, 'A senha atual não confere.');
  if (String(nova || '').length < 8) return erro(res, 400, 'A nova senha precisa ter pelo menos 8 caracteres.');
  db.prepare('UPDATE usuarios SET senha_hash = ?, trocar_senha = 0 WHERE id = ?').run(bcrypt.hashSync(String(nova), 10), u.id);
  res.json({ ok: true });
});

/* ---------------- usuários (analista) ---------------- */
const PERFIS = ['analista', 'solicitante'];
app.get('/api/usuarios', autenticar, somenteAnalista, (req, res) => {
  res.json(db.prepare('SELECT id, usuario, nome, perfil, ativo, trocar_senha AS trocarSenha, criado_em AS criadoEm FROM usuarios ORDER BY nome').all());
});
app.post('/api/usuarios', autenticar, somenteAnalista, (req, res) => {
  const usuario = texto(req.body.usuario, 80).toLowerCase();
  const nome = texto(req.body.nome, 120);
  const perfil = req.body.perfil;
  const senha = String(req.body.senha || '');
  if (!/^[a-z0-9._-]{3,80}$/.test(usuario)) return erro(res, 400, 'Usuário deve ter letras, números, ponto, hífen ou sublinhado (ex.: joao.silva).');
  if (!nome) return erro(res, 400, 'Informe o nome.');
  if (!PERFIS.includes(perfil)) return erro(res, 400, 'Perfil inválido.');
  if (senha.length < 5) return erro(res, 400, 'A senha inicial precisa ter pelo menos 5 caracteres.');
  if (db.prepare('SELECT 1 FROM usuarios WHERE usuario = ?').get(usuario)) return erro(res, 409, 'Esse usuário já existe.');
  const id = novoId();
  db.prepare('INSERT INTO usuarios (id, usuario, nome, perfil, senha_hash, ativo, trocar_senha, criado_em) VALUES (?,?,?,?,?,1,1,?)')
    .run(id, usuario, nome, perfil, bcrypt.hashSync(senha, 10), agora());
  res.json({ id });
});
app.put('/api/usuarios/:id', autenticar, somenteAnalista, (req, res) => {
  const u = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.params.id);
  if (!u) return erro(res, 404, 'Usuário não encontrado.');
  const nome = req.body.nome != null ? texto(req.body.nome, 120) : u.nome;
  const perfil = req.body.perfil != null ? req.body.perfil : u.perfil;
  const ativo = req.body.ativo != null ? (req.body.ativo ? 1 : 0) : u.ativo;
  if (!PERFIS.includes(perfil)) return erro(res, 400, 'Perfil inválido.');
  if (u.id === req.usuario.id && (perfil !== 'analista' || !ativo)) return erro(res, 400, 'Você não pode tirar seu próprio acesso de analista.');
  db.prepare('UPDATE usuarios SET nome = ?, perfil = ?, ativo = ? WHERE id = ?').run(nome, perfil, ativo, u.id);
  if (req.body.senha) {
    if (String(req.body.senha).length < 5) return erro(res, 400, 'A senha precisa ter pelo menos 5 caracteres.');
    db.prepare('UPDATE usuarios SET senha_hash = ?, trocar_senha = 1 WHERE id = ?').run(bcrypt.hashSync(String(req.body.senha), 10), u.id);
  }
  if (!ativo || req.body.senha) db.prepare('DELETE FROM sessoes WHERE usuario_id = ?').run(u.id);
  res.json({ ok: true });
});

/* ---------------- cadastros ---------------- */
function lerCadastros() {
  const c = parse(db.prepare("SELECT valor FROM config WHERE chave = 'cadastros'").get()?.valor) || {};
  return { destinos: c.destinos || [], fazendas: c.fazendas || [], fornecedores: c.fornecedores || [],
    proprietarios: c.proprietarios?.length ? c.proprietarios : ['Grupo', 'Núcleo IQ'], racas: c.racas || [], responsaveis: c.responsaveis || [] };
}
function gravarCadastros(c) {
  db.prepare("INSERT INTO config (chave, valor) VALUES ('cadastros', ?) ON CONFLICT(chave) DO UPDATE SET valor = excluded.valor").run(json(c));
}
app.get('/api/cadastros', autenticar, (req, res) => res.json(lerCadastros()));
app.put('/api/cadastros', autenticar, somenteAnalista, (req, res) => {
  const lista = k => Array.isArray(req.body[k]) ? req.body[k].map(v => texto(v, 120)).filter(Boolean) : [];
  const c = { destinos: unicos(lista('destinos')), fazendas: unicos(lista('fazendas')), fornecedores: unicos(lista('fornecedores')),
    proprietarios: [...new Set(lista('proprietarios'))], racas: unicos(lista('racas')), responsaveis: unicos(lista('responsaveis')) };
  if (!c.proprietarios.length) return erro(res, 400, 'Cadastre pelo menos um proprietário.');
  gravarCadastros(c);
  res.json(c);
});

/* ---------------- solicitações ---------------- */
const OPERACOES = ['Compra', 'Transferência', 'Trading'];
const SEXOS = ['Machos', 'Fêmeas'];
function linhaSol(r) {
  const d = parse(r.dados) || {};
  return { ...d, id: r.id, status: r.status, solicitanteId: r.usuario_id, criadoPorNome: r.criado_por_nome,
    criadoEm: r.criado_em, atualizadoEm: r.atualizado_em, ocId: r.oc_id, ocNumero: r.oc_numero, ocStatus: r.oc_status || null };
}
const SQL_SOL = `SELECT s.*, u.nome AS criado_por_nome, o.status AS oc_status FROM solicitacoes s
  LEFT JOIN usuarios u ON u.id = s.usuario_id LEFT JOIN ocs o ON o.id = s.oc_id`;

function validarSolicitacao(b) {
  const d = {
    operacao: b.operacao, sexo: b.sexo, raca: texto(b.raca, 80), qtd: parseInt(b.qtd, 10) || null,
    origem: texto(b.origem, 120), destino: texto(b.destino, 120), proprietario: texto(b.proprietario, 80),
    data: /^\d{4}-\d{2}-\d{2}$/.test(b.data || '') ? b.data : '', solicitante: texto(b.solicitante, 120),
    responsavel: texto(b.responsavel, 120), observacao: texto(b.observacao, 1000), contato: texto(b.contato, 60),
    preco: null,
  };
  if (d.operacao === 'Compra' && b.preco !== '' && b.preco != null && !isNaN(Number(b.preco))) d.preco = Number(b.preco);
  const c = lerCadastros();
  if (!OPERACOES.includes(d.operacao)) return { erro: 'Escolha o tipo de movimentação.' };
  if (!SEXOS.includes(d.sexo)) return { erro: 'Escolha machos ou fêmeas.' };
  if (!c.racas.includes(d.raca)) return { erro: 'Escolha uma raça do cadastro.' };
  if (!d.qtd || d.qtd < 1) return { erro: 'Informe quantas cabeças.' };
  if (!d.origem || !d.destino) return { erro: 'Informe origem e destino.' };
  if (!d.data) return { erro: 'Informe a data prevista.' };
  if (!d.solicitante) return { erro: 'Informe quem está solicitando.' };
  if (!c.responsaveis.includes(d.responsavel)) return { erro: 'Escolha um responsável do cadastro.' };
  if (!c.proprietarios.includes(d.proprietario)) d.proprietario = c.proprietarios[0];
  return { dados: d };
}

app.get('/api/solicitacoes', autenticar, (req, res) => {
  const rows = req.usuario.perfil === 'analista'
    ? db.prepare(SQL_SOL + ' ORDER BY s.criado_em DESC').all()
    : db.prepare(SQL_SOL + ' WHERE s.usuario_id = ? ORDER BY s.criado_em DESC').all(req.usuario.id);
  res.json(rows.map(linhaSol));
});

app.post('/api/solicitacoes', autenticar, (req, res) => {
  const v = validarSolicitacao(req.body); if (v.erro) return erro(res, 400, v.erro);
  const id = novoId(), t = agora();
  v.dados.historico = [{ em: t, status: 'enviada', por: req.usuario.nome }];
  db.prepare('INSERT INTO solicitacoes (id, usuario_id, status, dados, criado_em, atualizado_em) VALUES (?,?,?,?,?,?)')
    .run(id, req.usuario.id, 'enviada', json(v.dados), t, t);
  res.json({ id });
});

function pegarSol(id) { return db.prepare('SELECT * FROM solicitacoes WHERE id = ?').get(id); }

app.put('/api/solicitacoes/:id', autenticar, (req, res) => {
  const s = pegarSol(req.params.id);
  if (!s || s.usuario_id !== req.usuario.id) return erro(res, 404, 'Solicitação não encontrada.');
  if (!['enviada', 'ajuste'].includes(s.status)) return erro(res, 400, 'Essa solicitação já foi decidida e não pode mais ser alterada.');
  const v = validarSolicitacao(req.body); if (v.erro) return erro(res, 400, v.erro);
  const antigo = parse(s.dados) || {}, t = agora();
  v.dados.historico = [...(antigo.historico || []), { em: t, status: 'enviada', por: req.usuario.nome, nota: 'Corrigida e reenviada' }];
  db.prepare("UPDATE solicitacoes SET status = 'enviada', dados = ?, atualizado_em = ? WHERE id = ?").run(json(v.dados), t, s.id);
  res.json({ ok: true });
});

app.post('/api/solicitacoes/:id/cancelar', autenticar, (req, res) => {
  const s = pegarSol(req.params.id);
  if (!s || s.usuario_id !== req.usuario.id) return erro(res, 404, 'Solicitação não encontrada.');
  if (!['enviada', 'ajuste'].includes(s.status)) return erro(res, 400, 'Essa solicitação já foi decidida.');
  mudarStatusSol(s, 'cancelada', req.usuario.nome, null);
  res.json({ ok: true });
});

function mudarStatusSol(s, status, porNome, nota, extra = {}) {
  const d = parse(s.dados) || {}, t = agora();
  d.historico = [...(d.historico || []), { em: t, status, por: porNome, ...(nota ? { nota } : {}) }];
  if (status === 'ajuste' || status === 'recusada') d.motivo = nota; else if (status === 'enviada') d.motivo = null;
  d.analisadoPor = extra.analisadoPor || d.analisadoPor;
  db.prepare('UPDATE solicitacoes SET status = ?, dados = ?, atualizado_em = ?, oc_id = COALESCE(?, oc_id), oc_numero = COALESCE(?, oc_numero) WHERE id = ?')
    .run(status, json(d), t, extra.ocId || null, extra.ocNumero || null, s.id);
}

for (const [acao, status] of [['ajuste', 'ajuste'], ['recusar', 'recusada']]) {
  app.post(`/api/solicitacoes/:id/${acao}`, autenticar, somenteAnalista, (req, res) => {
    const s = pegarSol(req.params.id);
    if (!s) return erro(res, 404, 'Solicitação não encontrada.');
    if (!['enviada', 'ajuste'].includes(s.status)) return erro(res, 400, 'Essa solicitação já foi decidida.');
    const motivo = texto(req.body.motivo, 1000);
    if (!motivo) return erro(res, 400, 'Escreva o motivo.');
    mudarStatusSol(s, status, req.usuario.nome, motivo, { analisadoPor: req.usuario.nome });
    res.json({ ok: true });
  });
}

/* ---------------- OCs ---------------- */
function linhaOc(r) { return { ...(parse(r.dados) || {}), id: r.id, numero: r.numero, numeroBase: r.numero_base, status: r.status, fonte: r.fonte, solicitacaoId: r.solicitacao_id }; }
function proximoNumero() { return (db.prepare('SELECT MAX(numero_base) AS m FROM ocs').get().m || 0) + 1; }

app.get('/api/ocs', autenticar, somenteAnalista, (req, res) => {
  res.json({ ocs: db.prepare('SELECT * FROM ocs ORDER BY numero_base DESC, id DESC').all().map(linhaOc), proximo: proximoNumero() });
});

app.post('/api/solicitacoes/:id/gerar-oc', autenticar, somenteAnalista, (req, res) => {
  const s = pegarSol(req.params.id);
  if (!s) return erro(res, 404, 'Solicitação não encontrada.');
  if (!['enviada', 'ajuste'].includes(s.status)) return erro(res, 400, 'Essa solicitação já foi decidida.');
  const b = req.body;
  const num = parseInt(b.numero, 10);
  if (!num || num < 1) return erro(res, 400, 'Informe o número da OC.');
  if (!['Sim', 'Não'].includes(b.trava)) return erro(res, 400, 'Escolha se o gado será travado.');
  const linhas = (Array.isArray(b.linhas) ? b.linhas : []).map(l => ({
    origem: texto(l.origem, 120), qtd: parseInt(l.qtd, 10) || null, sequencia: texto(l.sequencia, 40) || null,
    preco: l.preco !== '' && l.preco != null && !isNaN(Number(l.preco)) ? Number(l.preco) : null, obs: texto(l.obs, 200) || null,
  })).filter(l => l.origem || l.qtd);
  if (!linhas.length || linhas.some(l => !l.origem || !l.qtd)) return erro(res, 400, 'Cada linha precisa de origem e quantidade.');
  const destino = texto(b.destino, 120);
  if (!destino) return erro(res, 400, 'Informe o destino.');
  const sd = parse(s.dados) || {};
  const operacao = OPERACOES.includes(b.operacao) ? b.operacao : sd.operacao;
  const t = agora(), id = String(num);
  const oc = {
    operacao, proprietario: texto(b.proprietario, 80), sexo: SEXOS.includes(b.sexo) ? b.sexo : sd.sexo,
    raca: texto(b.raca, 80) || null, responsavel: texto(b.responsavel, 120) || null, solicitante: sd.solicitante || null,
    qtdTotal: linhas.reduce((a, l) => a + (l.qtd || 0), 0), destino, data: /^\d{4}-\d{2}-\d{2}$/.test(b.data || '') ? b.data : null,
    trava: b.trava, observacao: texto(b.observacao, 1000) || null, linhas, geradaPor: req.usuario.nome, criadoEm: t,
    historico: [{ em: t, status: 'Pendente', por: req.usuario.nome, nota: 'Gerada a partir da solicitação ' + s.id.slice(0, 5).toUpperCase() + '. Aguardando viabilidade comercial da BU' }],
  };
  try {
    db.transaction(() => {
      if (db.prepare('SELECT 1 FROM ocs WHERE id = ? OR numero = ?').get(id, id)) throw new Error('DUP');
      db.prepare('INSERT INTO ocs (id, numero, numero_base, status, fonte, solicitacao_id, dados, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(id, id, num, 'Pendente', 'sistema', s.id, json(oc), t, t);
      mudarStatusSol(s, 'oc_gerada', req.usuario.nome, 'OC nº ' + id, { ocId: id, ocNumero: id, analisadoPor: req.usuario.nome });
      // nomes novos entram nos cadastros
      const c = lerCadastros();
      const tem = (lista, v) => lista.some(x => chave(x) === chave(v));
      let mudou = false;
      if (!tem(c.destinos, destino)) { c.destinos = unicos([...c.destinos, destino]); mudou = true; }
      for (const l of linhas) {
        if (operacao === 'Transferência') { if (!tem([...c.fazendas, ...c.destinos], l.origem)) { c.fazendas = unicos([...c.fazendas, l.origem]); mudou = true; } }
        else if (!tem([...c.fornecedores, ...c.fazendas, ...c.destinos], l.origem)) { c.fornecedores = unicos([...c.fornecedores, l.origem]); mudou = true; }
      }
      if (mudou) gravarCadastros(c);
    })();
  } catch (e) {
    if (e.message === 'DUP') return erro(res, 409, `A OC nº ${id} já existe. Use outro número.`);
    throw e;
  }
  res.json({ id });
});

const OC_STATUS = ['Pendente', 'Aberto', 'Finalizado', 'Cancelado'];
app.post('/api/ocs/:id/status', autenticar, somenteAnalista, (req, res) => {
  const r = db.prepare('SELECT * FROM ocs WHERE id = ?').get(req.params.id);
  if (!r) return erro(res, 404, 'OC não encontrada.');
  const st = req.body.status;
  if (!OC_STATUS.includes(st)) return erro(res, 400, 'Status inválido.');
  const d = parse(r.dados) || {}, t = agora();
  d.historico = [...(d.historico || []), { em: t, status: st, por: req.usuario.nome }];
  db.prepare('UPDATE ocs SET status = ?, dados = ?, atualizado_em = ? WHERE id = ?').run(st, json(d), t, r.id);
  res.json({ ok: true });
});

/* ---------------- erros e arquivos ---------------- */
app.use('/api', (req, res) => erro(res, 404, 'Rota não encontrada.'));
app.use((err, req, res, next) => { console.error(err); erro(res, 500, 'Erro interno. Tente de novo.'); });
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: PRODUCAO ? '1h' : 0 }));

app.listen(PORT, () => console.log(`Sistema de OCs rodando em http://localhost:${PORT}`));
