import sys, os
sys.path.append('..')
import common, sql
import csv
import pandas as pd
import numpy as np
from datetime import datetime

toolId = common.getToolId('OWASP Dependency-Check')
file=open('owasplog.txt','w')

def redesignColumns(df):
    keep=['ScanDate', 'DependencyName', 'DependencyPath', 'Description',
        'Identifiers','CPE', 'CVE','CWE', 
        'Vulnerability', 'Source', 
        'CVSSv2_Severity', 'CVSSv2_Score','CVSSv3_BaseSeverity', 'CVSSv3_BaseScore', 
       'CPE Confidence', 'Evidence Count' ]
    df=df[keep]
    new_names=['scandate', 'dependency', 'dependencyPath','description',
        'identifier','CPE' , 'CVE', 'CWE', 
        'vulnerability', 'source', 
        'CVSS2_severity', 'CVSS2_score','CVSS3_severity', 'CVSS3_score', 
        'confidence', 'evidenceCount' ]
    df.columns= new_names
    return df

def parseMavenIdentifier(dependency, identifier):
    print(dependency, identifier)
    
    #corener case hardcoding
    if 'dwr-2.0.7-mod' in dependency: 
        return 'org.openmrs.directwebremoting', 'dwr', '2.0.7-mod'
    if pd.isna(identifier) and 'gradle-wrapper' in dependency:
        return 'gradle', 'gradle-wrapper', '2.12'
    
    if ',' in identifier:
        print(dependency)
        identifier=identifier.split(',')[-1].strip()
    
    if identifier.startswith('pkg:maven/'):
        fullname = identifier[len('pkg:maven/'):]
        
        assert fullname.count('@') == 1
        fullname, version = fullname.split('@')
        
        assert fullname.count('/') == 1
        group, artifact = fullname.split('/')
        
        return group, artifact, version
    
    elif identifier.startswith('pkg:javascript/'):
        return parseJSidentifier(dependency, identifier)
        
    else:
        raise Exception('check this ', dependency, identifier)  
    
def getMavenPackageId(dependency: str, identifier: str, insertIfNotExists=False):
    group, artifact, version = parseMavenIdentifier(dependency, identifier)
    
    return common.getPackageId(group, artifact, version, 'maven', insertIfNotExists)

def parseJSidentifier(dependency, identifier):
    assert dependency.endswith('js')
    artifact = dependency.split(':')[-1]
    artifact = artifact[:-len('.js')]
    artifact=artifact.strip()
    
    fullname = identifier[len('pkg:javascript/'):]
    group='javascript'
    assert fullname.count('@') == 1
    version = fullname.split('@')[1].strip()
    
    if '-' + version in artifact:
        artifact = artifact[:-len('-' + version)]
    if '-v' + version in artifact:
        artifact = artifact[:-len('-v' + version)]
    if '-' + version + '.cus' in artifact:
        artifact = artifact[:-len('-' + version + '.cus')]
    
    
    return group, artifact, version


def parseNPMIdentifier(dependency, identifier):
    print(dependency, identifier)
    if ',' in identifier:
        file.write(dependency)
        identifier=identifier.split(',')[-1].strip()
        
    if identifier.startswith('pkg:npm/'):
        assert (dependency.split(':') == identifier[len('pkg:npm/'):].split('@') or '@' in dependency)
        group = 'npm'
        artifact, version = dependency.split(':')
        
        return group, artifact, version
    elif identifier.startswith('pkg:javascript/'):
        return parseJSidentifier(dependency, identifier)
        
    else:
        raise Exception('check this ', dependency, identifier)

def getNPMPackageId(dependency: str, identifier: str, insertIfNotExists = False):
    group, artifact, version = parseNPMIdentifier(dependency, identifier)
    
    return common.getPackageId(group, artifact, version, 'npm', insertIfNotExists)


def owaspVulnerabiltyId(dependency, source, cve, cwe, 
                    description, vulnerability, 
                    CVSS2_severity, CVSS2_score, CVSS3_severity, CVSS3_score ):
    
    if cve.startswith('CVE'):
        vulnId = common.getVulnerabilityId(cve, None)
        if vulnId > 0:
            return vulnId
        
    
    
    
    #non CVEs for OWASP can vary based on both dependency and description in cve columns
    sourceId = '-'.join(['OWASP', cve, dependency])
    vulnId = common.getVulnerabilityId(None, sourceId)
    if vulnId > 0 :
        return vulnId
    
    #nan values are creating issue for pymysql
    args = (dependency, source, cve, cwe, 
                    description, vulnerability, 
                    CVSS2_severity, CVSS2_score, CVSS3_severity, CVSS3_score)
    dependency, source, cve, cwe, description, vulnerability, \
    CVSS2_severity, CVSS2_score, \
    CVSS3_severity, CVSS3_score = map(common.changeNaNToNone, args)
    
    if description:
        description = description.replace('"',' ').replace('\\','')
    if vulnerability:
        vulnerability = vulnerability.replace('"',' ').replace('\\','')
    if description or vulnerability:
        if description:
            description += ' : '
        else:
            description = ''
        if vulnerability:
            description+=vulnerability
    
    insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None, source, 
                            None, sourceId,
                            None, description, 
                            CVSS2_score, CVSS2_severity, CVSS3_score, CVSS3_severity))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print(sourceId, ' already exists')
        else:
            raise Exception(str(error))
        
    vulnId = common.getVulnerabilityId(None, sourceId)
    
    if not cwe or 'NVD-CWE' in cwe:
        cwes = [-1]
    else:
        cwes=[]
        cweTexts=  cwe.split(',')
        for text in cweTexts:
            text=text.strip()
            text=text.split(' ')[0]
            assert text.startswith('CWE-')
            id= text[len('CWE-'):] 
            cwes.append(id)
    
    common.addCWEs(vulnId, cwes)
    
    return vulnId
           

def getOWASPReportAsDf(path, scanType):
    os.chdir(path)
    print('scanning ', path)
    depfilename="dependency-check-report.csv"
    
    start= datetime.now()
    
    if scanType=='maven':
        os.system('mvn org.owasp:dependency-check-maven:aggregate -Dformat=CSV -DenableExperimental')        
        file='./target/'+depfilename
        df= pd.read_csv(file, sep=',')
    
    if scanType == 'cli':
        os.system('dependency-check --enableExperimental --format CSV --scan ./')
        file=depfilename
        df= pd.read_csv(file, sep=',')
        
    
    end= datetime.now()
    
    return df, common.getTimeDeltaInMinutes(end-start)


def processMavenAlerts(mavenDf):
    df=mavenDf
    if len(df)==0:
        return
    
    df['packageId']=df.apply(lambda row: getMavenPackageId(row.dependency, row.identifier, insertIfNotExists=True), axis=1)
    df['dependencyId']=df.apply(lambda row: common.getDependencyId(row.repoId, row.packageId, row.toolId, insertIfNotExists=True), axis=1) 
    
    df=df[['scandate','dependencyId','vulnerabilityId','toolId','confidence']]

    df['id']=[np.nan]*len(df)
    df['severity']=[np.nan]*len(df)
    df['count']=[1]*len(df)
    
    df=df[['scandate','dependencyId','vulnerabilityId','toolId','confidence']]
    
    assert len(df[df.duplicated()])==0
    
    alerts = df.values
    insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
    for alert in alerts:
        for i in range(len(alert)):
            if pd.isna(alert[i]):
                alert[i]=None
        scandate,dependencyId,vulnerabilityId, toolId, confidence = alert
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, confidence, None, 1))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('maven alert exists already in db')     
            else:  
                raise Exception(str(error))

def processNPMAlerts(npmDf):
    df=npmDf
    if len(df)==0:
        return
    
    df['packageId']=df.apply(lambda row: getNPMPackageId(row.dependency, row.identifier, insertIfNotExists=True), axis=1)
    df['dependencyId']=df.apply(lambda row: common.getDependencyId(row.repoId, row.packageId, row.toolId, insertIfNotExists=True), axis=1) 
    df['dependencyPathId']=df.apply(lambda row: common.getDependencyPathId(row.dependencyPath), axis=1)
    
    df=df[['scandate','dependencyId','vulnerabilityId','dependencyPathId','toolId','confidence']]
    
    assert len(df[df.duplicated()])==0
    
   
    alerts=df.values
    
    insertQ = 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    for alert in alerts:
        for i in range(len(alert)):
            if pd.isna(alert[i]):
                alert[i]=None
        scandate,dependencyId,vulnerabilityId, dependencyPathId, toolId, confidence = alert
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 dependencyPathId, toolId, confidence, None, 1))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('npm alert exists already in db') 
            else:
                print((None,scandate,dependencyId,vulnerabilityId,
                                 dependencyPathId,
                                 toolId, None, None, 1))
                raise Exception(str(error)) 
     
def processAlerts(repoId, df):
    if len(df)==0:
        return
    df=redesignColumns(df)

    df['repoId']=[repoId]*len(df)
    df['toolId']=[toolId]*len(df)
    df['vulnerabilityId']=df.apply(lambda row: owaspVulnerabiltyId(row.dependency, row.source, row.CVE, row.CWE, \
                    row.description, row.vulnerability, \
                    row.CVSS2_severity, row.CVSS2_score, row.CVSS3_severity, row.CVSS3_score ), axis=1)
    
    #note the path comparison here. some are hard coded. discuss themselves
    npmDf = df[df['dependencyPath'].str.contains('/node_modules') | 
               df['dependencyPath'].str.contains('/npm') |
               df['dependencyPath'].str.contains('/package-lock.json')]
    mavenDf=df[df['dependencyPath'].str.contains('.m2/repository/') | 
               df['dependencyPath'].str.contains('src/main/webapp/') |
               df['dependencyPath'].str.contains('pom.xml')]
    
    
    print(repoId, len(mavenDf), len(npmDf), len(df))
    assert len(mavenDf) + len(npmDf) == len(df)

    processMavenAlerts(mavenDf)
    processNPMAlerts(npmDf)
    
def npmInstall():
    q  ='''select * from repoDependencyFiles rDF
        join repository r on rDF.repositoryId = r.id
        where file like %s'''
    results= sql.execute(q,('%package.json',))
    
    for item in results:
        path = '/Users/nasifimtiaz/openmrs/' + item['repoName']
        if '/' in item['file']:
            path = path + '/' + item['file']
            path=path[:-len('/package.json')]
        os.chdir(path)
        os.system('npm install')
    


if __name__=='__main__':
    mavenRepos= common.getWatchedRepos()
    npmRepos = common.getNpmPackageRepos()
    mavenScantime = 0
    npmScantime = 0
    
    #npmInstall()
    
    repos=common.getWatchedRepos()
    for path in repos:
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
        df, time =getOWASPReportAsDf(path, 'maven')
        if path in mavenRepos:
            mavenScantime += time
        if path in npmRepos:
            npmScantime += time 
        processAlerts(repoId, df)
    
    repos = common.getNonMavenProjects()
    for path in repos:
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
        df, time =getOWASPReportAsDf(path, 'cli')
        if path in mavenRepos:
            mavenScantime += time
        if path in npmRepos:
            npmScantime += time 
        processAlerts(repoId, df)

    paths = common.getSubdirectoryNPMpaths()
    for repoId in paths.keys():
        path=paths[repoId]
        df, time =getOWASPReportAsDf(path, 'cli')
        
        npmScantime += time #hardcoding as know all to be npm
        
        processAlerts(repoId, df)
        
    
    print(mavenScantime, npmScantime)
    common.addScanTime(toolId, mavenScantime, 'maven')
    common.addScanTime(toolId, npmScantime, 'npm')
    
    file.close()