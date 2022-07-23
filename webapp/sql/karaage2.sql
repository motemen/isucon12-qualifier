DROP TABLE IF EXISTS competition;
DROP TABLE IF EXISTS player;
-- DROP TABLE IF EXISTS player_score;

CREATE TABLE IF NOT EXISTS competition (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  title TEXT NOT NULL,
  finished_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,

  INDEX `tenant_idx` (`tenant_id`)
);

CREATE TABLE IF NOT EXISTS player (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  display_name TEXT NOT NULL,
  is_disqualified BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,

  INDEX `tenant_idx` (`tenant_id`)
);

CREATE TABLE IF NOT EXISTS player_score (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  player_id VARCHAR(10) CHARACTER SET ascii NOT NULL,
  competition_id VARCHAR(10) CHARACTER SET ascii NOT NULL,
  score BIGINT NOT NULL,
  row_num BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
