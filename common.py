import sql
import requests
import json 
import time
import os

def getPackageId(group, artifact, version,source='null'):
    selectQ= '''select * from package where
            `group`='{}' and artifact='{}' and version ='{}'
                     '''.format(group, artifact, version)
    results=sql.execute(selectQ)
    if not results:
        sql.execute("insert into package values(null,'{}','{}','{}','{}')".format(group, artifact, version,source))
        results=sql.execute(selectQ)

    return results[0]['id']

def getDependencyId(idrepo, idpackage):
    selectQ='''select id from dependency where 
            repositoryId={} and packageId={}'''.format(idrepo,idpackage)
    results = sql.execute(selectQ)
    # if not results:
    #     insertQ='''insert into dependencyTree values (null,
    #                 {},{},'external',null,null); '''.format(idmodule,idpackage)
    #     sql.execute(insertQ)
    #     results = sql.execute(selectQ)
    return results[0]['id']


def addFromRedhatApi(cve, idpackage):
    url='https://access.redhat.com/labs/securitydataapi/cve/'+cve
    data=json.loads(requests.get(url).content)
    description=(' '.join(x for x in data['details'])).replace('"','')
    severity2, score2, severity3, score3 = ['null']*4
    #TODO: No severity rating mentioned explicitly
    if 'cvss' in data.keys():
        score2= data['cvss']['cvss_base_score']
    if 'cvss3' in data.keys():
        score3= data['cvss3']['cvss3_base_score']
    insertQ='''insert into vulnerability values(null,
           {},null, "{}", null, null, null,"{}",null, {}, {}, {}, {} ); '''.format(
               idpackage, cve, description, severity2, str(score2), severity3, str(score3)
           )
    #print(insertQ)
    sql.execute(insertQ)

def addFromNvdApi(cve, idpackage):
    print("started", cve)
    url='https://services.nvd.nist.gov/rest/json/cve/1.0/'+cve
    data=json.loads(requests.get(url).content)
    print('ended')
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
    insertQ='''insert into vulnerability values(null,
           {},null, "{}", null, null, null,"{}",null, {}, {}, {}, {} ); '''.format(
               idpackage, cve, description, severity2, str(score2), severity3, str(score3)
           )
    sql.execute(insertQ)
    time.sleep(3)

def getRepoId(repo):
    results=sql.execute('select id from repository where repoName="{}"'.format(repo))
    if not results:
        raise Exception('repo not found')
    return results[0]['id']


def getWatchedRepos():
    mvn=os.popen('mvn openmrs-sdk:info -DserverId=distro-2-10-0').read().split('\n')[:-1]
    flag=False
    repos=[]
    for line in mvn:
        if line.startswith('[INFO] Projects watched for changes:'):
            flag=True
            continue
        if flag:
            line=line.strip()
            if line.endswith('[INFO]'):
                flag=False
            else:
                repos.append(line.split(' ')[-1])
                #repos.append('nasifimtiazohi/'+temp)
    return repos
if __name__=='__main__':
   pass
        
    
    