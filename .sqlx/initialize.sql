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