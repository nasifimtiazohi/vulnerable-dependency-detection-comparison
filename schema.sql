SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';
SET @OLD_TIME_ZONE=@@session.time_zone;

DROP SCHEMA IF EXISTS `openmrsvd` ;
CREATE SCHEMA IF NOT EXISTS `openmrsvd` DEFAULT CHARACTER SET utf8;
USE `openmrsvd` ;

CREATE TABLE `openmrsvd`.`modules` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `group` VARCHAR(45) NOT NULL,
  `artifact` VARCHAR(45) NOT NULL,
  `version` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX (`group`,`artifact`,`version`));

CREATE TABLE `openmrsvd`.`dependencyTree` (
  `idmodules` INT NOT NULL,
  `group` VARCHAR(45) NOT NULL,
  `artifact` VARCHAR(45) NOT NULL,
  `version` VARCHAR(45) NOT NULL,
  `packaging` VARCHAR(45) NULL,
  `scope` VARCHAR(45) NULL,
  `depth` INT NULL,
  PRIMARY KEY (`idmodules`, `group`, `artifact`, `version`));
