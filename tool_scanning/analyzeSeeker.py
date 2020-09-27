import os, sys
sys.path.append('..')
import common, sql
import json

toolId=common.getToolId('Seeker')
data=json.loads(open('seeker2-10-0.json','r').read())


def insertPackage(artifact,version):
    assert '%' not in version
    
    q='select * from package where artifact = %s'
    results=sql.execute(q,(artifact,))
    if results:
        group= results[0]['group']
        eco=results[0]['ecosystem']
    else:
        group = 'seeker'
        eco='seeker'
    
    q='insert into package values(%s,%s,%s,%s,%s)'
    sql.execute(q,(None,group,artifact,version,eco))
    
for component in data:
    if not component['Vulnerabilities']:
        #no vulnerability present
        continue
    
    #get package id
    artifact=component['Name']
    version=component['Version']
    if not version:
        version='%' #any version
    else:
        version+='%' #Some suffixes like RELEASE could be ignored in seeker
        
    selectQ='''select id from package
    where artifact=%s and version like %s'''
    results=sql.execute(selectQ,(artifact,version))
    if not results:
        insertPackage(artifact,version[:-1])
        results=sql.execute(selectQ,(artifact,version))
    packageId= results[0]['id']  
    
    labels = ','.join(component['Labels'])

    for vuln in component['Vulnerabilities']:
        if 'CVE' not in vuln.keys():
            raise Exception('checl this', vuln)
        cve=vuln['CVE']
        vulnId=common.getVulnerabilityId(cve,None)

        q='insert into seeker values(%s,%s,%s)'
        sql.execute(q,(packageId, vulnId, labels))
        