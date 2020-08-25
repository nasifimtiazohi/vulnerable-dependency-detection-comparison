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
    
    
def addSnykInfo(vuln, dependencyId):
    id=vuln['id']
    isUpgradable = vuln['isUpgradable']
    isPatchable = vuln['isPatchable']
    proprietary = vuln['proprietary']
    exploit = vuln['exploit']
    if 'parentDepType' in vuln:
        depType = vuln['parentDepType']
    else:
        depType=None
    if vuln['fixedIn']:
        fixedVersion = True
    else:
        fixedVersion = False
    
    insertQ=  'insert into snyk values(%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(id, dependencyId, fixedVersion,
                             isUpgradable,isPatchable,
                             depType, proprietary, exploit))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            return
    

def processNpmModules(repoId, npmModules):
    d={}
    for module in npmModules:
        project = module['projectName']
        d[project]={}
        
        for vuln in module['vulnerabilities']:
            artifact = vuln['moduleName']
            version = vuln['version']
            packageId = common.getPackageId('javascript',artifact,version)
            dependencyId = common.getDependencyId(repoId, packageId)

            ids = vuln['identifiers']
            vulnIds=[]
            
            if ids['CVE']:
                #CVE id present
                for cve in ids['CVE']:
                    vulnIds.append(common.getVulnerabilityId(cve, None))
            else:
                vulnIds.append(addSnykVulenrability(vuln))
            
            for vulnId in vulnIds:
                if packageId not in d[project]:
                    d[project][packageId] = [vulnId]
                else:
                    d[project][packageId].append(vulnId)
                
            addSnykInfo(vuln,dependencyId)
    
    return d
            
def processMavenModules(repoId, mavenModules):
    d={}
    for module in mavenModules:
        project = module['projectName']
        d[project]={}
        
        for vuln in module['vulnerabilities']:
            group= vuln['mavenModuleName']['groupId']
            artifact = vuln['mavenModuleName']['artifactId']
            version = vuln['version']
            packageId = common.getPackageId(group,artifact,version)
            dependencyId = common.getDependencyId(repoId, packageId)

            ids = vuln['identifiers']
            vulnIds=[]
            
            if ids['CVE']:
                #CVE id present
                for cve in ids['CVE']:
                    vulnIds.append(common.getVulnerabilityId(cve, None))
            else:
                vulnIds.append(addSnykVulenrability(vuln))
            
            for vulnId in vulnIds:
                if packageId not in d[project]:
                    d[project][packageId] = [vulnId]
                else:
                    d[project][packageId].append(vulnId)
                
            addSnykInfo(vuln,dependencyId)
    
    return d
            
def dedupe_vulns(repoId, d):
    vuln={}
    for module in d.keys():
        for packageId in d[module].keys():
            for vulnId in d[module][packageId]:
                if vulnId not in vuln:
                    vuln[vulnId] = {'count':1}
                    vuln[vulnId]['dependencyId'] = common.getDependencyId(
                                                    repoId, packageId)
                else:
                    vuln[vulnId]['count']+=1
    
    return vuln            
                         
def addMavenAlerts(vuln):
    scandate= datetime.now()
    for vulnerabilityId in vuln.keys():
        
        dependencyId = vuln[vulnerabilityId]['dependencyId']
        count= vuln[vulnerabilityId]['count']
        
        insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, None, None, count))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('alert exists already in db')       

def addNpmAlerts(vuln):
    scandate= datetime.now()
    for vulnerabilityId in vuln.keys():
        
        dependencyId = vuln[vulnerabilityId]['dependencyId']
        count= vuln[vulnerabilityId]['count']
        
        insertQ = 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, None, None, count))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('alert exists already in db')  
            
                    

def scanAndProcess(path):
    os.chdir(path)
    repo= path.split('/')[-1]
    repoId=common.getRepoId(repo)

    report= json.loads(os.popen('snyk test --all-projects --dev --json').read())
    
    mavenModules=[]
    npmModules=[]
    
    for module in report:
        if module['packageManager']=='npm':
            npmModules.append(module)
        elif module['packageManager'] == 'maven':
            mavenModules.append(module)
        else:
            print('outside npm maven found. see report for ', path)
    
    d = processNpmModules(repoId, npmModules)
    vuln = dedupe_vulns(repoId, d)
    addNpmAlerts(vuln)
    
    processMavenModules(repoId, mavenModules)
    vuln = dedupe_vulns(repoId, d)
    addMavenAlerts(vuln)
    

if __name__=='__main__':
    repos=common.getAllRepos()
    for path in repos:
        scanAndProcess(path)
