create table alert
(
    id              int auto_increment
        primary key,
    scandate        varchar(255) null,
    dependencyId    int          not null,
    vulnerabilityId int          not null,
    confidence      varchar(45)  null,
    tool            varchar(45)  not null,
    constraint alert_pk
        unique (dependencyId, vulnerabilityId, tool)
);

create table dependency
(
    id           int auto_increment
        primary key,
    repositoryId int not null,
    packageId    int not null,
    constraint dependency_pk
        unique (repositoryId, packageId)
);

create table dependencyTree
(
    repositoryId int          not null,
    module       varchar(255) not null,
    packageId    int          not null,
    scope        varchar(45)  null,
    depth        int          null,
    packaging    varchar(45)  null,
    constraint dependencyTree_pk
        unique (repositoryId, packageId, module, scope, packaging)
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

create table snykDuplicate
(
    vulnerabilityId int not null
        primary key,
    count           int not null
);

create table steady
(
    alertId           int         not null
        primary key,
    vulnerableVersion varchar(45) null,
    callGraph         varchar(45) null,
    unitTest          varchar(45) null,
    integrationTest   varchar(45) null
);

create table vulnerability
(
    id             int auto_increment
        primary key,
    packageId      int          null,
    source         varchar(255) null,
    CVE            varchar(45)  null,
    nonCVE         varchar(255) null,
    CWE            longtext     null,
    CPE            longtext     null,
    description    longtext     null,
    vulnerability  longtext     null,
    CVSS2_severity varchar(45)  null,
    CVSS2_score    float        null,
    CVSS3_severity varchar(45)  null,
    CVSS3_score    float        null,
    constraint vulnerability_pk
        unique (CVE, nonCVE, packageId)
);

