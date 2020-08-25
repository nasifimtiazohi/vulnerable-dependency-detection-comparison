import os, sys, json
sys.path.append('..')
import common, sql
import dateutil.parser as dt
from datetime import datetime

toolId= common.getToolId('Snyk')
        
def addSnykVulenrability(vuln):
    id = vuln['id']
    #first check if the sourceId was already inserted
    selectQ = 'select id from vulnerability where cveId is null and sourceId=%s'
    results = sql.execute(selectQ, (id,))
    
    if not results:
        cvssScore = vuln['cvssScore']
        severity = vuln['severity']
        title = vuln['title']
        publishDate = dt.parse(vuln['publicationTime'])
        
        insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        sql.execute(insertQ, (None, 'Snyk',
                            None, id, publishDate, title,
                            None, None, cvssScore, severity ))
    
        results = sql.execute(selectQ, (id,))
        
        cwes= vuln['identifiers']['CWE']
        common.addCWEs(results[0]['id'], cwes)
            
    return results[0]['id']


def constructDependencyPath(paths):
    assert type(paths) == list
    s = ''
    for i, path in enumerate(paths):
        if i!= 0:
            s+='->'
        s+=path
    return s
    
def addSnykInfo(vuln, repoId):
    snykId = vuln['id']
    dependencyPath = constructDependencyPath(vuln['from'])
    isUpgradable = vuln['isUpgradable']
    isPatchable = vuln['isPatchable']
    proprietary = vuln['proprietary']
    if 'parentDepType' in vuln:
        depType = vuln['parentDepType']
    else:
        depType=None
    
    
    insertQ=  'insert into snyk values(%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None, snykId, repoId, dependencyPath,
                             isUpgradable, isPatchable,
                              depType, proprietary))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print('snykinfo already present')
            return
    
def addVulnerabilityInfo(vulnId, vuln):
    if 'fixedIn' in vuln and vuln['fixedIn']:
        fixedVersion = True
    else:
        fixedVersion = False
    exploit = vuln['exploit']
    
    
    insertQ = 'insert into vulnerabilityInfoSnyk values (%s,%s,%s)'
    try:
        sql.execute(insertQ,(vulnId, fixedVersion, exploit))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print('vulnerability info snyk already present')
            return

def processNpmModules(repoId, npmModules):
    d = {}
    
    for module in npmModules:
        for vuln in module['vulnerabilities']:
            artifact = vuln['moduleName']
            version = vuln['version']
            packageId = common.getPackageId('javascript',artifact,version)
            dependencyId = common.getDependencyId(repoId, packageId)

            ids = vuln['identifiers']
            severity = vuln['severity']
            
            vulnIds=[]
            if ids['CVE']:
                #CVE id present
                for cve in ids['CVE']:
                    vulnId = common.getVulnerabilityId(cve, None)
                    vulnIds.append(vulnId)
                    addVulnerabilityInfo(vulnId, vuln)
            else:
                vulnId = addSnykVulenrability(vuln)
                vulnIds.append(vulnId)
                addVulnerabilityInfo(vulnId, vuln)
            
            for vulnId in vulnIds:
                if (vulnId, dependencyId) not in d:
                    d[(vulnId, dependencyId)] = {'count':1, 'severity':severity}
                else:
                    d[(vulnId, dependencyId)]['count']+=1
            
            addSnykInfo(vuln,repoId)
    
    return d
        
        
def processMavenModules(repoId, mavenModules):
    d={}
    
    for module in mavenModules:
        for vuln in module['vulnerabilities']:
            group= vuln['mavenModuleName']['groupId']
            artifact = vuln['mavenModuleName']['artifactId']
            version = vuln['version']
            packageId = common.getPackageId(group,artifact,version)
            dependencyId = common.getDependencyId(repoId, packageId)

            ids = vuln['identifiers']
            severity = vuln['severity']
            
            vulnIds=[]
            if ids['CVE']:
                #CVE id present
                for cve in ids['CVE']:
                    vulnId = common.getVulnerabilityId(cve, None)
                    vulnIds.append(vulnId)
                    addVulnerabilityInfo(vulnId, vuln)
            else:
                vulnId = addSnykVulenrability(vuln)
                vulnIds.append(vulnId)
                addVulnerabilityInfo(vulnId, vuln)
            
            for vulnId in vulnIds:
                if (vulnId, dependencyId) not in d:
                    d[(vulnId, dependencyId)] = {'count':1, 'severity':severity}
                else:
                    d[(vulnId, dependencyId)]['count']+=1
            
            addSnykInfo(vuln,repoId)
                    

    return d
                 
def addMavenAlerts(vuln):
    scandate= datetime.now()
    for (vulnerabilityId, dependencyId) in vuln.keys():
        count= vuln[(vulnerabilityId, dependencyId)]['count']
        severity = vuln[(vulnerabilityId, dependencyId)]['severity']
        
        insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, None, severity, count))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('alert exists already in db')       

def addNpmAlerts(vuln):
    scandate= datetime.now()
    for (vulnerabilityId, dependencyId) in vuln.keys():
        count= vuln[(vulnerabilityId, dependencyId)]['count']
        severity = vuln[(vulnerabilityId, dependencyId)]['severity']
        
        insertQ = 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, None, severity, count))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('alert exists already in db')  
            
                    

def scanAndProcess(path):
    os.chdir(path)
    repo= path.split('/')[-1]
    repoId=common.getRepoId(repo)
    
    print('scanning ', path)
    
    start=datetime.now()
    report = os.system('snyk test --all-projects --dev --json > snyk.json')
    end=datetime.now()
    diff= end - start
    scantime = common.getTimeDeltaInMinutes(diff)
    
    report = json.loads(open('snyk.json','r').read())
    
    mavenModules=[]
    npmModules=[]

    if type(report) == list:
        print('multi-project', len(report))
    elif type(report) == dict:
        report = [report]
        print('single project', len(report))
    
    for module in report:
        if module['packageManager']=='npm':
            npmModules.append(module)
        elif module['packageManager'] == 'maven':
            mavenModules.append(module)
        else:
            print('outside npm maven found. see report for ', path)
    
    npm_d = processNpmModules(repoId, npmModules)
    addNpmAlerts(npm_d)
    
    maven_d = processMavenModules(repoId, mavenModules)
    addMavenAlerts(maven_d)
    
    return scantime
    

if __name__=='__main__':
    #as we can't set a key on dependencyPath in snyk table
    # we make sure truncation here to avoid duplication
    sql.execute('truncate table snyk')
    
    repos=common.getAllRepos()
    scantime = 0
    for path in repos:
        scantime += scanAndProcess(path)
    
    common.addScanTime(toolId, scantime)
