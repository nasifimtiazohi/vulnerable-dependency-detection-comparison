SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';
SET @OLD_TIME_ZONE=@@session.time_zone;

DROP SCHEMA IF EXISTS `openMRS` ;
CREATE SCHEMA IF NOT EXISTS `openMRS` DEFAULT CHARACTER SET utf8;
USE `openMRS` ;

create table alert
(
    scandate        varchar(255) null,
    dependencyId    int          not null,
    vulnerabilityId int          not null
        primary key,
    confidence      varchar(45)  null,
    tool            varchar(45)  null
);

create table dependency
(
    id           int auto_increment
        primary key,
    repositoryId int         not null,
    packageId    int         not null,
    packaging    varchar(45) null,
    scope        varchar(45) null,
    depth        int         not null,
    constraint dependency_pk
        unique (repositoryId, packageId)
);

create table package
(
    id       int auto_increment
        primary key,
    `group`  varchar(255) null,
    artifact varchar(255) null,
    version  varchar(255) null,
    source   varchar(255) null,
    constraint package_pk_2
        unique (artifact, version)
);

create table repository
(
    id       int auto_increment
        primary key,
    `group`  varchar(255) null,
    artifact varchar(255) null,
    version  varchar(255) null,
    repoName varchar(255) not null,
    constraint repository_repo_name_uindex
        unique (repoName)
);

create table vulnerability
(
    id             int auto_increment
        primary key,
    packageId      int          null,
    source         varchar(255) null,
    CVE            varchar(45)  null,
    nonCVE         varchar(255) null,
    CWE            varchar(45)  null,
    CPE            varchar(45)  null,
    description    longtext     null,
    vulnerability  longtext     null,
    CVSS2_severity varchar(45)  null,
    CVSS2_score    float        null,
    CVSS3_severity varchar(45)  null,
    CVSS3_score    float        null,
    constraint vulnerability_pk
        unique (CVE, nonCVE)
);

