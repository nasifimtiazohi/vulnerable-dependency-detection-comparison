import os, sys
sys.path.append('../..')
from gh_graphql import getDependencyAlerts
import distro_information.prepareDistro as distro
import common, sql
import time, dateutil.parser as dt 
from datetime import datetime
toolId= common.getToolId('Github Dependabot')
token=os.environ['github_token']

def addGithubAdvisory(alert):
    vuln = alert['securityAdvisory']
    ghsa = vuln['ghsaId']
    vulnId = common.getVulnerabilityId(None, ghsa)
    if vulnId > 0:
        return vulnId
    
    description = vuln['description']
    publishDate = dt.parse(vuln['publishedAt'])
    q='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    sql.execute(q,(None, 'GitHub', None, ghsa, 
                publishDate, description,
                None, None, None, None))
    return common.getVulnerabilityId(None, ghsa)

    

def getCVE(alert):
    identifiers=alert['securityAdvisory']['identifiers'] 
    count = 0
    cve = None
    for id in identifiers:
        if id['type']=='CVE':
            count+=1
            cve = id['value']
            assert ',' not in cve
    assert count <= 1
    return cve


def processMavenAlert(repoId, alert, hm):
    group, artifact = alert['securityVulnerability']['package']['name'].split(':')
    version = alert['vulnerableRequirements'][2:]
    packageId = common.getPackageId(group, artifact, version, ecosystem='maven',insertIfNotExists=True)
    dependencyId = common.getDependencyId(repoId, packageId, idtool=toolId, insertIfNotExists=True)
    
    cve = getCVE(alert)
    if cve:
        vulnId = common.getVulnerabilityId(cve, None)
    else:
        vulnId = addGithubAdvisory(alert)
        
    severity = alert['securityAdvisory']['severity']
    
    if (dependencyId,vulnId, toolId) not in hm:
        hm[(dependencyId,vulnId, toolId)] = {'severity':severity, 'count':0}
    else:
        hm[(dependencyId,vulnId, toolId)]['count'] +=1  
               

def processNpmAlert(repoId, alert, hm):
    artifact = alert['securityVulnerability']['package']['name']
    group='npm'
    version = alert['vulnerableRequirements'][2:]
    packageId = common.getPackageId(group, artifact, version, ecosystem='npm',insertIfNotExists=True)
    dependencyId = common.getDependencyId(repoId, packageId, idtool=toolId, insertIfNotExists=True)
    
    
    cve = getCVE(alert)
    if cve:
        vulnId = common.getVulnerabilityId(cve, None)
    else:
        vulnId = addGithubAdvisory(alert)
        
    severity = alert['securityAdvisory']['severity']
    
    if (dependencyId,vulnId, toolId) not in hm:
        hm[(dependencyId,vulnId, toolId)] = {'severity':severity, 'count':0}
    else:
        hm[(dependencyId,vulnId, toolId)]['count'] +=1  
        
    

def processAlerts(repoId, alerts):
    mavenHM = {}
    npmHM = {}
    
    #process alerts
    for alert in alerts:
        ecosystem = alert['securityVulnerability']['package']['ecosystem']
        if ecosystem == 'MAVEN':
            processMavenAlert(repoId, alert, mavenHM)
        elif ecosystem == 'NPM':
            processNpmAlert(repoId, alert, npmHM)
        else:
            raise Exception("alert. see this one - ", alert)
    
    #add alerts
    for (dependencyId,vulnId, toolId) in mavenHM:
        severity = mavenHM[(dependencyId,vulnId, toolId)]['severity']
        count = mavenHM[(dependencyId,vulnId, toolId)]['count']
        q= 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(q,(None,None,dependencyId,vulnId, toolId,None,severity,1))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('maven alert exists already in db')     
            else:  
                raise Exception(str(error))
    
    for (dependencyId,vulnId, toolId) in npmHM:
        severity= npmHM[(dependencyId,vulnId, toolId)]['severity']
        count = npmHM[(dependencyId,vulnId, toolId)]['count']
        q= 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(q,(None,None,dependencyId,vulnId, None, toolId,None,severity,1))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('maven alert exists already in db')     
            else:  
                raise Exception(str(error))






if __name__=='__main__':
    repoRelaseMapping = distro.getRepoReleaseMapping()
    print(len(repoRelaseMapping))
    
    for repo in repoRelaseMapping.keys():
        repoId=common.getRepoId(repo)
        if repoId !=1:
            continue
        githubReponame = repo + '-' + repoRelaseMapping[repo]
        print(githubReponame)
        alerts=getDependencyAlerts('nasifimtiazohi', githubReponame)
        print(alerts)
        # print("{} has {} alerts".format(githubReponame,len(alerts)))
        # processAlerts(repoId, alerts)
        
        #to help api rate limit  
        time.sleep(3)
    
    

        