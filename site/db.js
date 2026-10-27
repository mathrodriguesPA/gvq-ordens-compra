'use strict';
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

function abrirBanco() {
  const arquivo = process.env.BANCO || path.join(__dirname, 'dados', 'ocs.sqlite');
  fs.mkdirSync(path.dirname(arquivo), { recursive: true });
  const db = new Database(arquivo);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id TEXT PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, nome TEXT NOT NULL,
      perfil TEXT NOT NULL CHECK (perfil IN ('analista','solicitante')),
      senha_hash TEXT NOT NULL, ativo INTEGER NOT NULL DEFAULT 1, trocar_senha INTEGER NOT NULL DEFAULT 0, criado_em TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessoes (
      token_hash TEXT PRIMARY KEY, usuario_id TEXT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
      criado_em TEXT NOT NULL, expira_em TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS config (chave TEXT PRIMARY KEY, valor TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS solicitacoes (
      id TEXT PRIMARY KEY, usuario_id TEXT NOT NULL REFERENCES usuarios(id), status TEXT NOT NULL,
      dados TEXT NOT NULL, oc_id TEXT, oc_numero TEXT, criado_em TEXT NOT NULL, atualizado_em TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_sol_usuario ON solicitacoes(usuario_id);
    CREATE TABLE IF NOT EXISTS ocs (
      id TEXT PRIMARY KEY, numero TEXT NOT NULL, numero_base INTEGER NOT NULL, status TEXT NOT NULL,
      fonte TEXT NOT NULL, solicitacao_id TEXT, dados TEXT NOT NULL, criado_em TEXT NOT NULL, atualizado_em TEXT NOT NULL);
  `);
  return db;
}
module.exports = { abrirBanco };
