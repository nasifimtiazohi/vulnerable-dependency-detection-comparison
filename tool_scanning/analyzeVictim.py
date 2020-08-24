import sys, os
sys.path.append('..')
import sql, common
import csv
import pandas as pd
from bs4 import BeautifulSoup
import numpy as np
from datetime import datetime

toolId= common.getToolId('Maven Security Versions')

def getVulns(table) -> dict:
    
    def getCVEids(cves, packageId):
        ids=[]
        for cve in cves:
            if not cve.startswith('CVE'):
                raise Exception('non cve vulnerability in victims report', cve)
            ids.append(common.getVulnerabilityId(packageId,cve,None))
        return ids
    
    rows=table.find_all('tr')
    d={}
    cur=None
    
    for row in rows:
        if row.find_all('th'):
            #new module found
            cur=row.getText().replace('\n','').replace(' ','')
            d[cur]={}
        else:
            #new alert found
            cols=row.find_all('td')
    
            package=cols[0].getText()
            group, artifact, version = package.split(':')
            packageId=common.getPackageId(group, artifact, version)
        
            cves=(cols[1].getText()).replace('\n','').replace(' ','').split(',')
            d[cur][packageId] = getCVEids(cves,packageId)
    
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

def addAlerts(vuln):
    scandate= datetime.now()
    for vulnerabilityId in vuln.keys():
        
        dependencyId = vuln[vulnerabilityId]['dependencyId']
        count= vuln[vulnerabilityId]['count']
        
        insertQ = 'insert into alert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,scandate,dependencyId,vulnerabilityId,
                                 toolId, None, None, count))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('alert exists already in db')
                     
                

def scanAndProcess(path):
    repo=path.split('/')[-1]
    repoId=common.getRepoId(repo)
    os.chdir(path)
    os.system('mvn com.redhat.victims.maven:security-versions:check')
    os.chdir(path+'/target')
    files=(os.popen("find . -type f -path */dependencies/* -name index.html").read()).split("\n")[:-1]
    
    assert len(files) == 1
    file=files[0]
    
    soup= BeautifulSoup(open(file).read(),'lxml')
    d=getVulns(soup.find_all('table')[0])
    vulns = dedupe_vulns(repoId, d)
    addAlerts(vulns)

if __name__=='__main__':
    repos=common.getWatchedRepos()
    for path in repos:
        scanAndProcess(path)