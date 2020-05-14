import sys, os
import sql, common
import csv
import pandas as pd
from bs4 import BeautifulSoup
import numpy as np

path= "/Users/nasifimtiaz/openmrs"
os.chdir(path)
files=(os.popen("find . -type f -path */dependencies/* -name index.html").read()).split("\n")[:-1]

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

def getModuleIdIfNotAlreadyProcessed(module):
    q='''select *
        from modules m
        join dependencyTree dt
            on m.id=dt.idmodule
        join alerts a
            on dt.id=a.iddependency
        where m.artifact='{}'
        and a.tool='victims' '''.format(module)
    results = sql.execute(q)
    if results:
        return -1
    q='select id from modules where artifact="{}"'.format(module)
    return sql.execute(q)[0]['id']



def insertVulns(idmodule,d):
    for k in d.keys():
        group, artifact, version = k.split(':')
        idpackage=common.getPackageId(group, artifact, version)
        iddependency=common.getDependencyId(idmodule, idpackage)
        for cve in d[k]:
            selectQ="select id from vulnerabilities where CVE='{}'".format(cve)
            results=sql.execute(selectQ)
            if not results:
                common.addFromNvdApi(cve,idpackage)
                results=sql.execute(selectQ)
            idvulnerability=results[0]['id']
            q="insert into alerts values(null, {},{},null,'victims');".format(
                str(iddependency),str(idvulnerability))
            sql.execute(q)
                

for file in files:
    soup= BeautifulSoup(open(file).read(),'lxml')
    d=getVulns(soup.find_all('table')[0])
    for k in d.keys():
        idmodule= getModuleIdIfNotAlreadyProcessed(k)
        if idmodule == -1:
            continue
        insertVulns(idmodule, d[k])
