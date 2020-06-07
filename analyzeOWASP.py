import sys, os
import common, sql
import csv
import pandas as pd
import numpy as np


def redesignColumns(df):
    keep=['ScanDate', 'DependencyName', 'Description',
        'Identifiers','CPE', 'CVE',
       'CWE', 'Vulnerability', 'Source', 'CVSSv2_Severity', 'CVSSv2_Score',
       'CVSSv3_BaseSeverity', 'CVSSv3_BaseScore', 'CPE Confidence' ]
    df=df[keep]
    new_names=['scandate', 'dependency', 'description',
        'package','CPE' , 'CVE',
       'CWE', 'vulnerability', 'source', 'CVSS2_severity', 'CVSS2_score',
       'CVSS3_severity', 'CVSS3_score', 'confidence' ]
    df.columns= new_names
    return df


def getPackageId(dependency, identifier):
    dep=str(dependency)
    if dep.endswith('.jar'):
        #handle exception cases
        if dep.count('jar') > 1:
            dep=dep.split('jar:')
            dep=dep[-1].strip()

        dep=dep[:-4]

        #handle exception case
        if dep == 'gradle-wrapper':
            artifact=dep
            selectQ='select id from package where artifact="{}" and version="undefined"'.format(artifact)
            results=sql.execute(selectQ)
            if not results:
                insertQ='insert into package values(null,null,"{}","undefined", "owasp")'.format(artifact)
                sql.execute(insertQ)
                results= sql.execute(selectQ)
            return results[0]['id']
        
        else:
            q='''select id
                from package
                where concat(artifact,'-',version) = '{}';'''.format(dep)
            try:
                return sql.execute(q)[0]['id']
            except Exception as e:
                raise Exception(q,e)
    else:
        #get name and version from the package
        templist=identifier.split("/")
        group=templist[-2]
        if ':' in group:
            group=group.split(':')[-1]
        temp=templist[-1]
        #TODO: error checking if not in desired format 
        temp=temp.split("@")
        artifact=temp[0]
        version=temp[1]
        source='owasp'
        return common.getPackageId(group,artifact,version,source)
    
def getDependencyId(repoId, packageId):
    selectQ='''select id from dependency where 
            repositoryId={} and packageId={}'''.format(repoId,packageId)
    results = sql.execute(selectQ)
    if not results:
        insertQ='''insert into dependency values (null,
                    {},{}); '''.format(repoId,packageId)
        sql.execute(insertQ)
        results = sql.execute(selectQ)
    return results[0]['id']
    





def getVulnerabiltyId(dependency, packageId, source, cve, cwe, cpe,
                    description, vulnerability, CVSS2_severity,
                    CVSS2_score, CVSS3_severity, CVSS3_score ):
    if cve.startswith('CVE'):
        CVE=cve
        nonCVE='None'
    else:
        #non CVEs for OWASP can vary based on both dependency and description in cve columns
        CVE='None'
        nonCVE= cve + " in " + dependency 

    #string cleaning
    cwe=cwe.replace('"',' ').replace('\\','')
    cpe=cpe.replace('"',' ').replace('\\','')
    description=description.replace('"',' ').replace('\\','')
    vulnerability=vulnerability.replace('"',' ').replace('\\','')


    selectQ= '''select id from vulnerability
        where packageId="{}" and CVE ="{}" and nonCVE="{}"'''.format(packageId,CVE,nonCVE)
    results=sql.execute(selectQ)
    if results:
        return results[0]['id']
    else:
        insertQ='''insert into vulnerability values (null,
        {},"{}","{}","{}","{}","{}","{}","{}","{}",{},"{}",{});'''.format(packageId,
        source,CVE,nonCVE,cwe,cpe,description,vulnerability,CVSS2_severity,CVSS2_score,
        CVSS3_severity,CVSS3_score)
        try:
            sql.execute(insertQ)
        except Exception as e:
            print(insertQ, e)
            exit()
        return sql.execute(selectQ)[0]['id']



#path to openmrs
def process_alerts(path):
    print(path, " has started")
    os.chdir(path)
    repo=path.split('/')[-1]
    repoId=common.getRepoId(repo)

    if common.alertAlreadyProcessed(repoId,'owasp'):
        return

    os.system('mvn org.owasp:dependency-check-maven:aggregate -Dformat=CSV')

    depfilename="dependency-check-report.csv"
    #files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]
    files=['./target/'+depfilename] #will only read the root file

    for file in files:
        df= pd.read_csv(file, sep=',')
        
        if len(df) == 0:
            continue
        
        df=redesignColumns(df)

        df['repoId']=[repoId]*len(df)

        df['packageId']=df.apply(lambda row: getPackageId(row.dependency, row.package),axis=1)
        
        df = df.astype(object).where(pd.notnull(df),'null')

        df['vulnerabilityId']=df.apply(lambda row: getVulnerabiltyId(row.dependency, row.packageId, row.source, 
                        row.CVE, row.CWE, row.CPE,
                        row.description, row.vulnerability, row.CVSS2_severity,
                        row.CVSS2_score, row.CVSS3_severity, row.CVSS3_score ), axis=1)

        df['dependencyId']=df.apply(lambda row: getDependencyId(row.repoId, row.packageId), axis=1) 
        df['tool']='owasp'
        df=df[['scandate','dependencyId','vulnerabilityId','confidence','tool']]

        df['id']=[np.nan] *len(df)
        df.drop_duplicates()
        sql.load_df('alert',df)


if __name__=='__main__':
    repos=common.getWatchedRepos()
    for path in repos:
        os.chdir(path)
        os.system('mvn org.owasp:dependency-check-maven:aggregate -Dformat=CSV')
        process_alerts(path)
    
    