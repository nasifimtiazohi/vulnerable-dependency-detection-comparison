import os, sys
import common, sql
import json

data=json.loads(open('seeker.json','r').read())
t=0
for component in data:
    if component['Vulnerabilities']:
        #get package id
        artifact=component['Name']
        version=component['Version']
        if not version:
            version='%'
        selectQ='''select id from package
        where artifact='{}' and version like '{}%' 
        '''.format(artifact,version)
        results=sql.execute(selectQ)
        if not results:
            if version=='%':
                version='null'
            else:
                version = "'"+version+"'"
            q='''insert into package values (null,
            null, '{}',{},'seeker')
            '''.format(artifact,version)
            sql.execute(q)
            results=sql.execute(selectQ)
        if not results:
            selectQ='''select id from package
                    where artifact='{}' '''.format(artifact)
            results=sql.execute(selectQ)
        idpackage=results[0]['id']
        for vuln in component['Vulnerabilities']:
            cve=vuln['CVE']
            q='select id from vulnerability where CVE="{}"'.format(cve)
            results=sql.execute(q)
            if not results:
                common.addFromNvdApi(cve,idpackage)
                results=sql.execute(q)
            idvulnerability=results[0]['id']
            
            #no dependency id for seeker
            q="insert into alert values(null,null,{},{},null,'seeker');".format(
                        str(idpackage), str(idvulnerability))
            try:
                sql.execute(q)
            except:
                print(q)
print(t)