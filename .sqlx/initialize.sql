-- Create the database if it doesn't exist.
CREATE DATABASE IF NOT EXISTS `sdk`;

-- Use the database.
USE `sdk`;

-- Initialize the accounts table.
CREATE TABLE IF NOT EXISTS `accounts` (
                            `uid`           INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
                            `name`          VARCHAR(64) UNIQUE,
                            `email`         VARCHAR(128) UNIQUE,
                            `mobile`        VARCHAR(16) UNIQUE,
                            `password`      TEXT,
                            `state`         INTEGER NOT NULL DEFAULT 1,
                            `epoch_created` INTEGER NOT NULL
);

-- Initialize the devices table.
CREATE TABLE IF NOT EXISTS `devices` (
                            `uid`            INTEGER NOT NULL,
                            `device`         VARCHAR(512) NOT NULL,
                            `epoch_lastseen` INTEGER NOT NULL,
                            PRIMARY KEY (`uid`, `device`)
);

-- Initialize the data tables.
CREATE TABLE IF NOT EXISTS `login_tokens` (
                            `uid`    INTEGER NOT NULL,
                            `token`  TEXT NOT NULL,
                            `device` VARCHAR(512) NOT NULL,
                            PRIMARY KEY (`uid`, `device`)
);

-- This table is not used in `pancake`.
CREATE TABLE IF NOT EXISTS `realnames` (
                            `uid`           INTEGER NOT NULL PRIMARY KEY,
                            `name`          TEXT NOT NULL,
                            `identity`      VARCHAR(128) NOT NULL UNIQUE,
                            `is_realperson` INTEGER NOT NULL DEFAULT 0
);

-- Initialize the tickets tables.
CREATE TABLE IF NOT EXISTS `reactivate_tickets` (
                            `ticket` VARCHAR(32) NOT NULL PRIMARY KEY,
                            `uid`    INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS `grant_tickets` (
                           `ticket` VARCHAR(32) NOT NULL,
                           `device` VARCHAR(512) UNIQUE,
                           `uid`    INTEGER NOT NULL UNIQUE,
                           `code`   TEXT,
                            PRIMARY KEY (`uid`, `device`)
);
