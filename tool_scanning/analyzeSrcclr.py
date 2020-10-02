import os, sys
sys.path.append('..')
import sql, common
import subprocess, shlex
import json
from dateutil import parser as dt

toolId = common.getToolId('SourceClear')

path = '/Users/nasifimtiaz/Downloads/scans'
os.chdir(path)

lines= subprocess.check_output(shlex.split('ls'),encoding='437').split('\n')[:-1]
failures=['openmrs-module-adminui-1.3.0',
            'openmrs-module-attachments-2.2.0',
            'openmrs-module-coreapps-1.28.0',
            'openmrs-module-metadatasharing-1.6.0',
            'openmrs-module-reportingcompatibility-2.0.6',
            'openmrs-module-uicommons-2.12.0',
            'openmrs-owa-sysadmin-1.2']


def getSrcClrVulnerability(data):
    publishDate = dt.parse(data['disclosureDate'])
    description = data['title'] + ' ' + data['overview']
    cvssScore = data['cvssScore']
    source = 'SourceClear'
    
    selectQ = 'select * from vulnerability where source=%s and description=%s'
    results = sql.execute(selectQ , (source, description))
    
    if not results:
        id = source + str(hash(description))
        insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        sql.execute(insertQ, (None, source,
                                None, id, publishDate, description,
                                None, None, cvssScore, None ))

    results = sql.execute(selectQ , (source, description))
    return results[0]['id']
    
def process_vulnerabilities(repoId, data, allLibraries):
    #get vuln id
    srcclrId=True
    assert 'cve' in data.keys()
    if data['cve'] is not None:
        cveId = 'CVE-' + data['cve']
        vulnId = common.getVulnerabilityId(cveId, None)
        if vulnId > 0:
            srcclrId=False
        print(cveId)
    if srcclrId:
        vulnId = getSrcClrVulnerability(data)
    
    
    depIds = []
    for library in data['libraries']:
        ref = library['_links']['ref']
        assert ref.startswith('/records/0/libraries/')
        ref = ref[len('/records/0/libraries/'):]
        ref = ref.split('/')
        p , v = int(ref[0]), int(ref[-1])
        package = allLibraries[p]
        group = package['coordinate1']
        artifact = package['coordinate2']
        version = package['versions'][v]['version']
        packageId = common.getPackageId(group,artifact,version,'maven',True)
        dependencyId = common.getDependencyId(repoId, packageId, toolId, True)
        depIds.append(dependencyId)
    
    for dependencyId in depIds:
        insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
        try:
            sql.execute(insertQ,(None,None,dependencyId,vulnId,
                                 toolId, None, None, 1/len(depIds)))
        except sql.pymysql.IntegrityError as error:
            if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
                #TODO update scandate
                print('maven alert exists already in db')     
            else:  
                raise Exception(str(error))

def allMavenLibraries(allLibraries):
    for library in allLibraries:
        if library['coordinateType'] != 'MAVEN':
            return False
    return True


def processVulnMethods(repoId,data):
    for vuln in data:
        assert len(vuln['calls']) ==1
        call = vuln['calls'][0]
        callChains = len(call['callChains'])
        className = call['method']['className']     
        descriptor = call['method']['descriptor']
        method = call['method']['methodName']   
        
        q = 'insert into srcclrCallChains values(%s,%s,%s,%s,%s)'
        sql.execute(q,(repoId, className, descriptor, method, callChains))

for line in lines:
    if line in failures:
        continue
    repoName = '-'.join(line.split('-')[:-1])
    repoId = common.getRepoId(repoName)
    filename=path +'/'+line + '/scan.json'
    with open(filename,'r') as file:
        print(repoName)
        records= json.loads(file.read())['records']
        assert len(records) ==1
        data=records[0]
        allLibraries = data['libraries']
        assert allMavenLibraries(allLibraries)
        # if 'vulnerabilities' in data.keys():
        #     for vuln in data['vulnerabilities']:
        #         process_vulnerabilities(repoId, vuln, allLibraries)
        processVulnMethods(repoId,data['vulnMethods'])