import sys, os
import sql, common
import csv
import pandas as pd
from bs4 import BeautifulSoup
import numpy as np



def getVulns(table) -> dict:
    rows=table.find_all('tr')
    d={}
    cur=None
    for row in rows:
        if row.find_all('th'):
            #new module found
            cur=row.getText().replace('\n','').replace(' ','')
            d[cur]={}
        else:
            cols=row.find_all('td')
            package=cols[0].getText()
            cves=(cols[1].getText()).replace('\n','').replace(' ','').split(',')
            d[cur][package]=cves
    return d



def insertVulns(repoId,d):
    for k in d.keys():
        group, artifact, version = k.split(':')
        idpackage=common.getPackageId(group, artifact, version)
        iddependency=common.getDependencyId(repoId, idpackage)
        for cve in d[k]:
            if not cve.startswith('CVE'):
                raise Exception('non cve vulnerability in victims report')
            selectQ="select id from vulnerability where CVE='{}'".format(cve)
            results=sql.execute(selectQ)
            if not results:
                print("start NVD api looking")
                common.addFromNvdApi(cve,idpackage)
                print("end NVD api looking")
                results=sql.execute(selectQ)
            idvulnerability=results[0]['id']
            #check if already inserted
            q='''select * from alert where dependencyId={} and 
                vulnerabilityId={} and tool='victims' '''.format(str(iddependency),str(idvulnerability))
            results=sql.execute(q)
            if results:
                continue
            q="insert into alert values(null,null, {},{},null,'victims');".format(
                str(iddependency),str(idvulnerability))
            sql.execute(q)
                



if __name__=='__main__':
    repos=common.getWatchedRepos()
    for path in repos:
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
        os.chdir(path)
        os.system('mvn com.redhat.victims.maven:security-versions:check')
        os.chdir(path+'/target')
        files=(os.popen("find . -type f -path */dependencies/* -name index.html").read()).split("\n")[:-1]
        for file in files:
            soup= BeautifulSoup(open(file).read(),'lxml')
            d=getVulns(soup.find_all('table')[0])
            for k in d.keys(): #each key is a module 
                insertVulns(repoId, d[k])