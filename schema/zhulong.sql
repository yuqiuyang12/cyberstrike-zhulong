CREATE TABLE zl_chains (
  id               TEXT PRIMARY KEY,
  conversation_id  TEXT NOT NULL,
  goal_id          TEXT NOT NULL DEFAULT '',
  run_id           TEXT NOT NULL DEFAULT '',
  finding_key      TEXT NOT NULL,
  title            TEXT NOT NULL DEFAULT '',
  rung             INTEGER NOT NULL DEFAULT 0,
  state            TEXT NOT NULL DEFAULT 'open',
  hypothesis       TEXT NOT NULL DEFAULT '',
  blocker_evidence TEXT NOT NULL DEFAULT '',
  note             TEXT NOT NULL DEFAULT '',
  target_asset      TEXT NOT NULL DEFAULT '',
  hypothesis_type   TEXT NOT NULL DEFAULT '',
  target_model_ref  TEXT NOT NULL DEFAULT '',
  enumeration_space TEXT NOT NULL DEFAULT '',
  unverified_space  TEXT NOT NULL DEFAULT '',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
, max_reachable_rung INTEGER NOT NULL DEFAULT -1, next_rung_blocker TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX ux_zl_chains_open_finding
  ON zl_chains(conversation_id, goal_id, finding_key) WHERE state = 'open';
CREATE INDEX ix_zl_chains_conv
  ON zl_chains(conversation_id, state, rung DESC);
CREATE INDEX ix_zl_chains_state
  ON zl_chains(state, rung DESC);
CREATE INDEX ix_zl_chains_asset
  ON zl_chains(target_asset, state);
CREATE TABLE zl_chain_attempts (
  id           TEXT PRIMARY KEY,
  chain_id     TEXT NOT NULL,
  attempt_no   INTEGER NOT NULL,
  rung         INTEGER NOT NULL DEFAULT 0,
  payload      TEXT NOT NULL DEFAULT '',
  evidence_ref TEXT NOT NULL DEFAULT '',
  verdict      TEXT NOT NULL,
  summary      TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  FOREIGN KEY (chain_id) REFERENCES zl_chains(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ux_zl_chain_attempts_no
  ON zl_chain_attempts(chain_id, attempt_no);
CREATE INDEX ix_zl_chain_attempts_chain
  ON zl_chain_attempts(chain_id, attempt_no);

-- conversations 三列(服务端 database.go 已做幂等迁移;以下供离线核对/重建参考)
ALTER TABLE conversations ADD COLUMN unattended_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conversations ADD COLUMN continue_hint TEXT NOT NULL DEFAULT '';
ALTER TABLE conversations ADD COLUMN unattended_since TEXT NOT NULL DEFAULT '';
