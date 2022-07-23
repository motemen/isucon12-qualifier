DELETE FROM tenant WHERE id > 100;
DELETE FROM visit_history WHERE created_at >= '1654041600';
UPDATE id_generator SET id=2678400000 WHERE stub='a';
ALTER TABLE id_generator AUTO_INCREMENT=2678400000;

--
DROP TABLE IF EXISTS competition;
DROP TABLE IF EXISTS player;
-- DROP TABLE IF EXISTS player_score;

CREATE TABLE competition IF NOT EXISTS (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  title TEXT NOT NULL,
  finished_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,

  INDEX `tenant_idx` (`tenant_id`)
);

CREATE TABLE player IF NOT EXISTS (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  display_name TEXT NOT NULL,
  is_disqualified BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,

  INDEX `tenant_idx` (`tenant_id`)
);

CREATE TABLE player_score IF NOT EXISTS (
  id VARCHAR(10) CHARACTER SET ascii NOT NULL PRIMARY KEY,
  tenant_id BIGINT NOT NULL,
  player_id VARCHAR(10) CHARACTER SET ascii NOT NULL,
  competition_id VARCHAR(10) CHARACTER SET ascii NOT NULL,
  score BIGINT NOT NULL,
  row_num BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

DELETE FROM player_score WHERE created_at > 1654041599;
