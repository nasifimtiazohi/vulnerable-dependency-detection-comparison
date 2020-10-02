import os, sys, json
sys.path.append('..')
import common, sql
import dateutil.parser as dt
from datetime import datetime
import json

snykIds = set()


def process_vuln(vuln):
    if vuln['id'] in snykIds:
        return 
    
    changeType=None
    snykId = vuln['id']
    version = vuln['version']

    version = version.split('.')
    major = version[0]
    minor = version[1]
    
    
    assert 'fixedIn' in vuln.keys()
    
    if len(vuln['fixedIn']) == 0:
        changeType = 'No fix'
    
    majorFixes = []
    minorFixes = []
    for fixedVersion in vuln['fixedIn']:
        fixedVersion = fixedVersion.split('.')
        majorFixes.append(fixedVersion[0])
        minorFixes.append(fixedVersion[1])
        
    if major not in  majorFixes:
        changeType = 'major'
    elif minor not in minorFixes:
        changeType = 'minor'
    else:
        changeType = 'patchMinor'
    
    q='insert into snykExtra values(%s,%s,%s,%s)'
    sql.execute(q,(snykId,changeType,vuln['version'],','.join(vuln['fixedIn'])))
    
    snykIds.add(snykId)
    
        
    
    
    
    

repos=common.getAllRepos()
mavenRepos= common.getWatchedRepos()
npmRepos = common.getNpmPackageRepos()

for path in repos:
    filename = path + '/snyk.json'
    with open(filename,'r') as file:
        data= json.loads(file.read())
        if type(data) != list:
            data=[data]
        for module in data:
            if module['packageManager'] != 'maven':
                continue
            for vuln in module['vulnerabilities']:
                process_vuln(vuln)