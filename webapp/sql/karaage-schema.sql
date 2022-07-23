USE `isuports`;

CREATE TABLE IF NOT EXISTS billing (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `tenant_id` BIGINT UNSIGNED NOT NULL,
  `competition_id` VARCHAR(255) NOT NULL,
  `player_count` BIGINT NOT NULL,
  `visitor_count` BIGINT NOT NULL,
  `billing_player_yen` BIGINT NOT NULL,
  `billing_visitor_yen` BIGINT NOT NULL,
  `billing_yen` BIGINT NOT NULL,
  `updated_at` BIGINT NOT NULL,
  PRIMARY KEY  (`id`),
  INDEX `tenant_id_competition_id_idx` (`tenant_id`, `competition_id`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;
