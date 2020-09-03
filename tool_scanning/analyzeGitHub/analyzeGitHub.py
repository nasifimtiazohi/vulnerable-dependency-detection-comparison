import os, sys
sys.path.append('../..')
from gh_graphql import getDependencyAlerts
import common, sql
import time, dateutil.parser as dt 
from datetime import datetime
toolId= common.getToolId('Github Dependabot')
token=os.environ['github_token']

def addGithubAdvisory(vuln):
    ghsa = vuln['ghsaId']
    vulnId = common.getVulnerabilityId(None, ghsa)
    if vulnId is None:
        description = vuln['description']
        publishDate = dt.parse(vuln['publishedAt'])
        q='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        sql.execute(q,(None, 'GitHub', None, ghsa, 
                    publishDate, description,
                    None, None, None, None))
        return common.getVulnerabilityId(None, ghsa)
    else:
        return vulnId



def processMavenAlert(repoId, alert):
    package= alert['securityVulnerability']['package']['name'].split(':')
    group=package[0]
    artifact=package[1]
    query='''select *
        from dependency d
        join package p
        on d.packageId=p.id
        where d.repositoryId={}
        and p.`group`='{}'
        and p.artifact='{}';'''.format(repoId, group, artifact)
    try:
        dependencyId = sql.execute(query)[0]['id'] 
    except:
        print(repoId, group, artifact)
        exit()
    #take the first one in case of multiple versions present
    #Note: GitHub does not present version within its alert
    
    identifiers = alert['securityAdvisory']['identifiers'] 
    cve= ghsa = None
    for id in identifiers:
        if id['type'] == 'CVE':
            cve = id['value']
        elif id['type'] == 'GHSA':
            ghsa = id['value']
    
    if cve:
        vulnId = common.getVulnerabilityId(cve, None)
    else:
        vulnId = addGithubAdvisory(alert['securityAdvisory'], ghsa)
        
    severity = alert['securityAdvisory']['severity']
        
    q= 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(q,(None,None,dependencyId,vulnId, toolId,None,severity,None))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print('alert already exists')    

def processNpmAlert(repoId, alert):
    artifact = alert['securityVulnerability']['package']['name']
    group='javascript'
    query='''select *
        from dependency d
        join package p
        on d.packageId=p.id
        where d.repositoryId={}
        and p.`group`='{}'
        and p.artifact='{}';'''.format(repoId, group, artifact)
    try:
        dependencyId = sql.execute(query)[0]['id'] 
    except:
        print(repoId, group, artifact)
        exit()
    #take the first one in case of multiple versions present
    #Note: GitHub does not present version within its alert
    
    identifiers = alert['securityAdvisory']['identifiers'] 
    cve= ghsa = None
    for id in identifiers:
        if id['type'] == 'CVE':
            cve = id['value']
        elif id['type'] == 'GHSA':
            ghsa = id['value']
    
    if cve:
        vulnId = common.getVulnerabilityId(cve, None)
    else:
        vulnId = addGithubAdvisory(alert['securityAdvisory'], ghsa)
        
    severity = alert['securityAdvisory']['severity']
        
    q= 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(q,(None,None,dependencyId,vulnId, toolId,None,severity,None))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print('alert already exists') 

def processAlerts(owner, repo):
    print('processing', repo)
    repoId=common.getRepoId(repo)
    alerts=getDependencyAlerts(owner, repo)

    #process alerts
    for alert in alerts:
        ecosystem = alert['securityVulnerability']['package']['ecosystem']
        if ecosystem == 'MAVEN':
            processMavenAlert(repoId, alert)
        elif ecosystem == 'NPM':
            processNpmAlert(repoId, alert)
        else:
            print("alert. see this one - ", alert)
        
    #to help api rate limit  
    time.sleep(3)


if __name__=='__main__':
    paths = common.getAllRepos()
    for path in paths:
        repo = path.split('/')[-1]
        #repoId= common.getRepoId(repo)
        processAlerts('nasifimtiazohi',repo)
        