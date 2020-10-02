import sql
import requests
import json 
import time
import os
from dateutil import parser as dt
import hashlib
import logging, coloredlogs
import pandas as pd
coloredlogs.install()


def getPackageId(group, artifact, version, ecosystem=None, insertIfNotExists = False):
    selectQ= 'select * from package where artifact=%s and version =%s'
    results=sql.execute(selectQ,(artifact, version))
    if not results:
        print(group,artifact,version)
        assert ' ' not in artifact and ' ' not in version and version not in artifact
        logging.info('new package found: %s, %s, %s',group, artifact, version)
        assert insertIfNotExists
        assert ecosystem
        sql.execute("insert into package values(null,%s,%s,%s,%s)"
                    ,(group, artifact, version, ecosystem))
        results=sql.execute(selectQ,(artifact, version))

    return results[0]['id']

def getDependencyId(idrepo, idpackage, idtool=None, insertIfNotExists = False):
    selectQ='''select id from dependency where 
            repositoryId=%s and packageId=%s'''
    results = sql.execute(selectQ,(idrepo,idpackage))
    if not results:
        logging.info('new dependency found: %s',idpackage)
        assert insertIfNotExists
        insertQ = 'insert into dependency values(%s,%s,%s)'
        sql.execute(insertQ,(None,idrepo,idpackage))
        results = sql.execute(selectQ,(idrepo,idpackage))
        iddependency= results[0]['id']
    
        #check if this dependency was in deptree (maven or npm)
        q='''select * from
            (select packageId
            from mavenDependencyTree
            union
            select packageId from
            npmDependencyTree) t
            where packageId=%s;'''
        check = sql.execute(q,(idpackage,))
        if not check:
            q='insert into dependencyFoundByTool values(%s,%s)'
            assert idtool
            sql.execute(q,(iddependency,idtool))
    
    iddependency= results[0]['id']
    return iddependency

def addFromNvdApi(cve):
    url='https://services.nvd.nist.gov/rest/json/cve/1.0/'+cve
    
    print('fetching cve started', url)
    response=requests.get(url)
    while response.status_code != 200 :
        if 'Unable to find' in response.text:
            #REJECTED CVE
            q='insert into rejectedCVEs values(%s)'
            try:
                sql.execute(q,(cve,))
            except sql.pymysql.IntegrityError as error:
                if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                    print(cve, ' already exists')
                else:
                    raise Exception(str(error))
            return -1
        print(response.content)
        time.sleep(3)
        response=requests.get(url)
    print('fetched cve: ',cve)
    
    data=json.loads(response.content)
    data=data['result']['CVE_Items'][0]
    
    publishDate=dt.parse(data['publishedDate'])
    
    temp=data['cve']['problemtype']['problemtype_data'][0]['description']
    cwes=[]
    for t in temp:
        if 'CWE' in t['value']:
            if not 'NVD' in t['value']:
                cwes.append(int(t['value'].split('-')[1].strip()))    
            else:
                cwes.append(t['value'])
    
    description=data['cve']['description']['description_data'][0]['value']
    description=description.replace('"','')
    
    
    severity2, score2, severity3, score3 = [None] * 4
    if 'impact' in data.keys():
        data=data['impact']
        if 'baseMetricV2' in data.keys():
            t=data['baseMetricV2']
            severity2=t['severity']
            score2=t['cvssV2']['baseScore']
        if 'baseMetricV3' in data.keys():
            t=data['baseMetricV3']
            severity3= t['cvssV3']['baseSeverity']
            score3=t['cvssV3']['baseScore']
    
    insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None, 'NVD', 
                            cve, None, 
                            publishDate, description, 
                            score2, severity2, score3, severity3))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print(cve, ' already exists')
        else:
            raise Exception(str(error))
    
    idvulnerability = getVulnerabilityId(cve, None)
    addCWEs(idvulnerability, cwes)
    
    return 1

def addCWEs(vulnerabilityId, cwes):
    q='insert into vulnerabilityCWE values(%s,%s)'
    for cwe in cwes:
        if type(cwe) != int:
            cwe=-1 #'NVD-CVE-Noinfo or other"
            print(cwe, ' cwe does not have an integer id')
        try:
            sql.execute(q,(vulnerabilityId,cwe))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                return
            else:
                raise Exception(str(error))
        

def getRepoId(repo):
    results=sql.execute('select id from repository where repoName=%s',(repo,))
    if not results:
        raise Exception('repo not found')
    return results[0]['id']


def getWatchedRepos():
    os.chdir('/Users/nasifimtiaz/openmrs')
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


def getNpmPackageRepos():
    q='''select repositoryId, repoName, file
        from repoDependencyFiles rDF
        join repository r on rDF.repositoryId = r.id
        where file like %s;'''
    results=sql.execute(q,('%package.json',))

    repos={}
    for item in results:
        repoPath = '/Users/nasifimtiaz/openmrs/'+item['repoName']
        repoId=item['repositoryId']
        if '/' not in item['file']:
            repos[repoId] = repoPath
        else:
            packagePath= item['file'].split('/')[:-1] #cut package.json filename
            repos[repoId] = repoPath + '/' + '/'.join(packagePath)
    
    paths = []
    for k in repos.keys():
        paths.append(repos[k])
    
    return paths

def getNonMavenProjects():
    repos=['/Users/nasifimtiaz/openmrs/openmrs-owa-sysadmin']
    return repos

def getAllRepos():
    return getWatchedRepos() + getNonMavenProjects()

def getToolId(name):
    selectQ = 'select id from tool where name=%s'
    results=sql.execute(selectQ,(name,))
    if not results:
        insertQ='insert into tool values(%s,%s)'
        sql.execute(insertQ,(None,name))
        results=sql.execute(selectQ,(name,))
    return results[0]['id']
        
def getVulnerabilityId(cveId, sourceId):
    def selectId():
        nonlocal cveId, sourceId
        if cveId and not sourceId:
            selectQ='''select id from vulnerability where
                         cveId=%s and sourceId is null'''
            return sql.execute(selectQ,(cveId))
        else:
            selectQ='''select id from vulnerability where
                        cveId is null and sourceId=%s'''
            return sql.execute(selectQ,(sourceId))
        
    
    results = selectId()
        
    if not results:
        if cveId and not sourceId:
            e = addFromNvdApi(cveId)
            if e==-1:
                #unable to find the cve
                return e
        else:
            return -1
    
        results = selectId()
    
    return results[0]['id']

def getTimeDeltaInMinutes(diff):
    return (diff.days*1440 + diff.seconds/60)

def addScanTime(toolId, minutes, ecosystem):
    #see if already exists
    selectQ= 'select * from scanMinutes where toolId = %s'
    results = sql.execute(selectQ, (toolId,))
    if not results:
        q= 'insert into scanMinutes values(%s,%s,%s)'
        sql.execute(q,(toolId,None,None))
        
    if ecosystem == 'maven':    
        q='update scanMinutes set maven=%s where toolId=%s'
        sql.execute(q,(minutes, toolId))
    elif ecosystem == 'npm':
        q='update scanMinutes set npm=%s where toolId=%s'
        sql.execute(q,(minutes, toolId))

def encrypt_string(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

def getDependencyPathId(path):
    h = encrypt_string(path)
    selectQ = 'select id from dependencyPath where hash=%s'
    results = sql.execute(selectQ,(h,))
    if not results:
        insertQ = 'insert into dependencyPath values (%s,%s,%s)'
        sql.execute(insertQ,(None,h,path))
        results = sql.execute(selectQ,(h,))
    return results[0]['id']

def changeNaNToNone(val):
    if pd.isna(val):
        return None
    else:
        return val


def getSubdirectoryNPMpaths():
    q='''select * from repoDependencyFiles rDF
        join repository r on rDF.repositoryId = r.id
        where file like %s and file not like %s'''
    results = sql.execute(q,('%package.json','package.json'))
    hm = {}
    for item in results:
        path = '/Users/nasifimtiaz/openmrs/' + item['repoName'] +'/' + item['file']
        path=path[:-len('/package.json')]
        repoId = item['repositoryId']
        
        assert repoId not in hm #TODO change for future types
        
        hm[repoId]=path
    
    return hm





if __name__=='__main__':
    print(getSubdirectoryNPMpaths())