import sys, os
sys.path.append('..')
import common, sql
import csv
import pandas as pd
import numpy as np
from datetime import datetime
from dateutil import parser as dt
import json 

toolId = common.getToolId('NPM Audit')

def getNPMVulnerability(data):
    sourceId = 'NPM-'+str(data['id'])
    publishDate = dt.parse(data['created'])
    description = data['title']+data['overview']
    
    insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None, 'NPM', 
                            None, sourceId,
                            publishDate, description, 
                            None, None, None, None))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print(sourceId, ' already exists')
        else:
            raise Exception(str(error))
    
    return common.getVulnerabilityId(None, sourceId)

def readAdvisories(advisories):
    '''
    Get advisory list from npm audit
    retrieve corresponding vulnerabilityId 
    and returns the mapping
    '''
    hm={}
    severity = {}
    for k in advisories.keys():
        data=advisories[k]
        vulnIds = []
        
        flag = True #True if no valid CVE associated 
        if 'cves' in data.keys() and len(data['cves'])>0:
            for cve in data['cves']:
                assert cve.startswith('CVE')
                vulnId = common.getVulnerabilityId(cve, None)
                if vulnId > 0:
                    vulnIds.append(vulnId)
                    severity[vulnId] = data['severity']
                    flag=False
        if flag:
            vulnId= getNPMVulnerability(data)
            vulnIds.append(vulnId)
            severity[vulnId] = data['severity']
        
        hm[data['id']]=vulnIds
    
    return hm, severity


def getNPMDependencyId(path):
    if '>' in path:
        package=path.split('>')[-1]
    else:
        package = path #depth 1
    
    q='''select d.id from dependency d
        join package p on d.packageId = p.id
        join repository r on d.repositoryId = r.id
        where p.artifact=%s
        and r.id=%s
        order by p.version desc
        limit 1; '''
    return sql.execute(q,(package, repoId))[0]['id']

def addVulnerabilities(repoId, data, vulnMapping, severity):
    hm={}
    for action in data:
        for cur in action['resolves']:
            vulnIds = vulnMapping[cur['id']]
            dependencyId = getNPMDependencyId(cur['path'])
            dependencyPathId = common.getDependencyPathId(cur['path'])
            
            for vulnId in vulnIds:
                tup = (dependencyId, vulnId, dependencyPathId)
                if tup not in hm:
                    hm[tup]=1
                else:
                    hm[tup]+=1
                
    for (dependencyId, vulnId, dependencyPathId) in hm.keys():          
        q = 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        sql.execute(q,(None, None, dependencyId, vulnId, dependencyPathId,
                    toolId, None, severity[vulnId], hm[(dependencyId, vulnId, dependencyPathId)]))


def addNpmAuditTable(repoId, actions):
    for action in actions:
        act = action['action']
        resolves = len(action['resolves'])
        module = action['module']
        if 'target' in action:
            target = action['target']
        else:
            target=None
        if 'isMajor' in action:
            isMajor = action['isMajor']
        else:
            isMajor=None
            
        q='insert into npmAudit values (%s,%s,%s,%s,%s,%s,%s)'
        sql.execute(q,(None, repoId, act, isMajor, module, target, resolves))
        
        
               
      
def getPackageJsonFilePaths():
    #Note: for now we only have one path per repo
    #to generalize we would need to fix that
    q='''select * from repoDependencyFiles rDF
        join repository r on rDF.repositoryId = r.id
        where file like %s'''
    results=sql.execute(q,'%package.json')
    paths = {}
    for item in results:
        repoId = item['repositoryId']
        path = '/Users/nasifimtiaz/openmrs/' + item['repoName'] + '/' + item['file'] 
        path=path[:-len('/package.json')]  
        paths[repoId]=path
    
    return paths    

def addAuditFixResults(repoId, data):
    validActions = ['added','removed','updated','moved','failed']
    q='insert into npmAuditFix values(%s,%s,%s,%s,%s,%s,%s)'
    for k in data.keys():
        if k not in validActions:
            continue
        for item in data[k]:
            action= item['action']
            name = item['name']
            version = item['version']
            path =  item['path']
            if 'previousVersion' in item:
                prevVersion = item['previousVersion']
            else:
                prevVersion =None
            if 'previousPath' in item:
                prevPath = item['previousPath']
            else:
                prevPath = None
            
            sql.execute(q,(repoId, action, name, version, path, prevVersion, prevPath))


def runNPMAudit(repoId, path):    
    os.chdir(path)
    print('scanning repo: ',repoId)
    
    #ensure npm install
    os.system('npm install')
    
    filename= 'npmaudit.json'
    os.system('npm audit --json > {}'.format(filename))
    data= json.loads(open(filename).read())
    vulnMapping, severity = readAdvisories(data['advisories'])
    addVulnerabilities(repoId, data['actions'], vulnMapping, severity)
    addNpmAuditTable(repoId, data['actions'])
    
    filename='npmauditfix.json'
    os.system('npm audit fix --dry-run --json > {}'.format(filename))
    data= json.loads(open(filename).read())
    addAuditFixResults(repoId, data)


def truncateRelevantData():
    q='delete from npmAlert where toolId=%s'
    sql.execute(q,(toolId,))
    
    truncates=['truncate table npmAudit', 'truncate table npmAuditFix']
    for q in truncates:
        sql.execute(q)
    
     
if __name__=='__main__':
    truncateRelevantData()
    paths = getPackageJsonFilePaths()
    for repoId in paths.keys():
        runNPMAudit(repoId, paths[repoId])
    

        