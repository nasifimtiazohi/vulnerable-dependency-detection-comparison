import sql
import requests
import json 
import time

def getPackageId(group, artifact, version):
    selectQ= '''select * from packages where
            `group`='{}' and artifact='{}' and version ='{}'
                     '''.format(group, artifact, version)
    results=sql.execute(selectQ)
    # if not results:
    #     sql.execute("insert into packages values(null,'{}','{}','{}')".format(group, artifact, version))
    #     results=sql.execute(selectQ)
    #NOTE: what if not found. Need to track them as error will throw
    return results[0]['id']

def getDependencyId(idmodule, idpackage):
    selectQ='''select id from dependencyTree where 
            idmodule={} and idpackage={}'''.format(idmodule,idpackage)
    results = sql.execute(selectQ)
    # if not results:
    #     insertQ='''insert into dependencyTree values (null,
    #                 {},{},'external',null,null); '''.format(idmodule,idpackage)
    #     sql.execute(insertQ)
    #     results = sql.execute(selectQ)
    return results[0]['id']

def addFromNvdApi(cve, idpackage):
    url='https://services.nvd.nist.gov/rest/json/cve/1.0/'+cve
    data=json.loads(requests.get(url).content)
    data=data['result']['CVE_Items'][0]
    description=data['cve']['description']['description_data'][0]['value']
    description=description.replace('"','')
    data=data['impact']
    severity2, score2, severity3, score3 = ['null']*4
    if 'baseMetricV2' in data.keys():
        t=data['baseMetricV2']
        severity2='"'+ t['severity'] +'"'
        score2=t['cvssV2']['baseScore']
    if 'baseMetricV3' in data.keys():
        t=data['baseMetricV3']
        severity3='"'+ t['cvssV3']['baseSeverity']+'"'
        score3=t['cvssV3']['baseScore']
    insertQ='''insert into vulnerabilities values(null,
           {},null, "{}", null, null, null,"{}",null, {}, {}, {}, {} ); '''.format(
               idpackage, cve, description, severity2, str(score2), severity3, str(score3)
           )
    sql.execute(insertQ)

if __name__=='__main__':
    #nvdapi('CVE-2019-10210',3)
    pass
    