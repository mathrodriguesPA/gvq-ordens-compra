'use strict';
// Carga inicial: cadastros, OCs da planilha e os usuários de teste.
// Pode rodar mais de uma vez: só cria o que ainda não existe.
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { abrirBanco } = require('./db');
const db = abrirBanco();
const agora = new Date().toISOString();

if (!db.prepare("SELECT 1 FROM config WHERE chave = 'cadastros'").get()) {
  db.prepare("INSERT INTO config (chave, valor) VALUES ('cadastros', ?)").run(JSON.stringify(require('./dados-iniciais/cadastros.json')));
  console.log('Cadastros carregados.');
}

const ocs = require('./dados-iniciais/ocs-planilha.json');
const ins = db.prepare('INSERT OR IGNORE INTO ocs (id, numero, numero_base, status, fonte, solicitacao_id, dados, criado_em, atualizado_em) VALUES (?,?,?,?,?,NULL,?,?,?)');
let n = 0;
db.transaction(() => {
  for (const o of ocs) {
    const { id, numero, numeroBase, status, ...resto } = o;
    resto.historico = [{ em: agora, status, nota: 'Importada da planilha' }];
    n += ins.run(id, String(numero), numeroBase || 0, status, 'planilha', JSON.stringify(resto), agora, agora).changes;
  }
})();
console.log(`${n} OCs da planilha importadas.`);

const usuarios = [
  { usuario: 'matheus.souza', nome: 'Matheus Souza', perfil: 'analista', senha: '12345' },
  { usuario: 'matheus.silveira', nome: 'Matheus Silveira', perfil: 'solicitante', senha: '12345' },
];
for (const u of usuarios) {
  if (db.prepare('SELECT 1 FROM usuarios WHERE usuario = ?').get(u.usuario)) continue;
  db.prepare('INSERT INTO usuarios (id, usuario, nome, perfil, senha_hash, ativo, trocar_senha, criado_em) VALUES (?,?,?,?,?,1,1,?)')
    .run(crypto.randomBytes(9).toString('base64url'), u.usuario, u.nome, u.perfil, bcrypt.hashSync(u.senha, 10), agora);
  console.log(`Usuário criado: ${u.usuario} (${u.perfil})`);
}
