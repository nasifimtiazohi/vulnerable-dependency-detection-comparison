import os, sys
sys.path.append('..')
import sql, common
import json
import distro_information.prepareDistro as distro
from dateutil import parser as dt
from datetime import datetime 

toolId= common.getToolId('Steady')

hm={
    'vulnerableVersion' : 1,
    'unknown':2,
    'nonVulnerableVersion': 3,
    'noLibraryCodeAtAll':4,
    'nonVulnerableLibraryCode':5,
    'vulnerableLibraryCode':6            
    }
inv_hm = {v:k for k, v in hm.items()}

def addSteadyVulnerability(vuln):
    #process this vuln
    sourceId=vuln['bug']['id']
    vulnId = common.getVulnerabilityId(None,sourceId)
    if vulnId > 0:
        return vulnId
    
    insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    sql.execute(insertQ, (None, 'Steady',
                        None, sourceId, None, None,
                        None, None, None, None ))
    
    return common.getVulnerabilityId(None,sourceId)
    
def getAlertId(scandate, dependencyId, vulnerabilityId):
    print(scandate, dependencyId, vulnerabilityId)
    insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                toolId, None, None, 1))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            #TODO update scandate
            print('maven alert exists already in db')     
        else:  
            raise Exception(str(error))   
    
    selectQ= '''select id from mavenAlert where dependencyId=%s
                and vulnerabilityId=%s and toolId=%s'''
    return sql.execute(selectQ,(dependencyId,vulnerabilityId,toolId))[0]['id']
    

def processReport(repoName, repoId):
    filename = repoName + '-vulas.json'
    with open(filename,'r') as file:
        data= json.loads(file.read())['vulasReport']
        
        if 'vulnerabilities' not in data.keys() or len(data['vulnerabilities'])==0:
            return

        scandate= data['generatedAt']
        
        vulnerabilities = data['vulnerabilities']

        for vuln in vulnerabilities:
            
            #get package id
            package=vuln['filename']
            if not package.endswith('.jar') or 'jar' in package[:-4]:
                #second condition ensures single package
                raise Exception('package not jar',package)

            package=package[:-4]
            q='''select id
                from package
                where concat(artifact,'-',version) = %s;'''
            packageId=sql.execute(q,(package,))[0]['id']
            dependencyId=common.getDependencyId(repoId,packageId)
                
            
            steadyId = True
            #get cve id
            if vuln['bug']['id'].startswith('CVE') and not 'CVE' in vuln['bug']['id'][3:]:
                #second condition ensures single CVE
                cve= vuln['bug']['id']
                if len(cve.split('-'))>3:
                    #some in vulas has extra addendums
                    print("check",cve)
                    cve='-'.join(x for x in cve.split('-')[:3])
                
                vulnerabilityId=common.getVulnerabilityId(cve,None)
                if vulnerabilityId > 0:
                    steadyId = False
                
            if steadyId:
                vulnerabilityId=addSteadyVulnerability(vuln)
                

            
            integrationTest=[]
            #DONE: write in a way so that first it can be run for only unit test
            #then again for integration test as well
            #check if already alert is pushed for the first three
            
            alertId = getAlertId(scandate,dependencyId,vulnerabilityId)
            
            vulnerableVersion=[]
            staticAnalysis=[]
            unitTest=[]
            
            for module in vuln['modules']:
                #get the static and dynamic analysis results into a separate table
                vulnerableVersion.append(hm[module['containsVulnerableCode']])
                staticAnalysis.append(hm[module['potentiallyExecutesVulnerableCode']])
                unitTest.append(hm[module['actuallyExecutesVulnerableCode']])
            
            vv=max(vulnerableVersion)
            sa=max(staticAnalysis)
            ut=max(unitTest)

            q='insert into steady values(%s,%s,%s,%s,%s)'
            try:
                sql.execute(q,(alertId,inv_hm[vv],inv_hm[sa],inv_hm[ut],None))
            except sql.pymysql.IntegrityError as error:
                if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                    #TODO update scandate
                    print('maven alert exists already in steady db')     
                else:  
                    raise Exception(str(error))
                
            #after running integration test ut will change
            # alertId=results[0]['id']
            # integrationTest=[]
            # for module in vuln['modules']:
            #     integrationTest.append(hm[module['actuallyExecutesVulnerableCode']])
            # it=max(integrationTest)
            # q='''update alert set integrationTest='{}'
            #         where alertId={} '''.format(inv_hm[it],alertId)
            # print(q)
    
    


def getScanTime(repoName):
    print(repoName)
    filename= repoName+'-log.txt'
    with open (filename, 'r') as file:
        lines= file.readlines()
        if lines:
            time = lines[-1]
        else:
            time='00:05:00.000000'
    
    hour, min, sec = time.split(':')
    return int(hour)*60 + int(min)
    
        


if __name__=='__main__':
    repoRelaseMapping = distro.getRepoReleaseMapping()
    reportPath = '/Users/nasifimtiaz/Desktop/runSteady/reports'
    os.chdir(reportPath)
    time = 0
    for repo in repoRelaseMapping.keys():
        if repo == 'openmrs-owa-sysadmin':
            continue
        repoName = repo + '-' + repoRelaseMapping[repo]
        repoId = common.getRepoId(repo)
        time += getScanTime(repoName)
        processReport(repoName, repoId)
    
    common.addScanTime(toolId, time, 'maven')
        
    
        
       
