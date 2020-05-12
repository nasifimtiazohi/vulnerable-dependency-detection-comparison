import sys, os
import sql
import csv
import pandas as pd

def getModuleId(module):
    results=sql.execute('select id from modules where artifact="{}"'.format(module))
    if not results:
        raise Exception('module not found')
    return results[0]['id']

def redesignColumns(df):
    keep=['idmodule','ScanDate', 'DependencyName', 'Description',
        'Identifiers','CPE', 'CVE',
       'CWE', 'Vulnerability', 'Source', 'CVSSv2_Severity', 'CVSSv2_Score',
       'CVSSv3_BaseSeverity', 'CVSSv3_BaseScore', 'CPE Confidence' ]
    df=df[keep]
    new_names=['idmodule','scandate', 'dependency', 'description',
        'package','CPE' , 'CVE',
       'CWE', 'vulnerability', 'source', 'CVSS2_severity', 'CVSS2_score',
       'CVSS3_severity', 'CVSS3_score', 'confidence' ]
    df.columns= new_names
    return df


    
def getDependencyId(idmodule, idpackage):
    selectQ='''select id from dependencyTree where 
            idmodule={} and idpackage={}'''.format(idmodule,idpackage)
    results = sql.execute(selectQ)
    if not results:
        insertQ='''insert into dependencyTree values (null,
                    {},{},'external',null,null); '''.format(idmodule,idpackage)
        sql.execute(insertQ)
        results = sql.execute(selectQ)
    return results[0]['id']
    


def addPackage(group,artifact,version):
    q="select id from packages where `group`='{}' and artifact='{}' and version ='{}'".format(group,artifact,version)
    results=sql.execute(q)
    if not results:
        sql.execute("insert into packages values (null,'{}','{}','{}');".format(group,artifact,version))
        results=sql.execute(q)
    return sql.execute(q)[0]['id']
def getPackageId(dependency, identifier):
    dep=str(dependency)
    if dep.endswith('.jar'):
        dep=dep[:-4]
        q='''select id
            from packages
            where concat(artifact,'-',version) = '{}';'''.format(dep)
        return sql.execute(q)[0]['id']
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
        return addPackage(group,artifact,version)


def getVulnerabiltyId(idpackage, source, cve, cwe, cpe,
                    description, vulnerability, CVSS2_severity,
                    CVSS2_score, CVSS3_severity, CVSS3_score ):
    if cve.startswith('CVE'):
        CVE=cve
        nonCVE='None'
    else:
        CVE='None'
        nonCVE=cve

    #string cleaning
    cwe=cwe.replace('"','\\"')
    cpe=cpe.replace('"','\\"')
    description=description.replace('"','\\"')
    vulnerability=vulnerability.replace('"','\\"')


    selectQ= '''select id from vulnerabilities
        where idpackage="{}" and CVE ="{}" and nonCVE="{}"'''.format(idpackage,CVE,nonCVE)
    results=sql.execute(selectQ)
    if results:
        return results[0]['id']
    else:
        insertQ='''insert into vulnerabilities values (null,
        {},"{}","{}","{}","{}","{}","{}","{}","{}",{},"{}",{});'''.format(idpackage,
        source,CVE,nonCVE,cwe,cpe,description,vulnerability,CVSS2_severity,CVSS2_score,
        CVSS3_severity,CVSS3_score)
        try:
            sql.execute(insertQ)
        except Exception as e:
            print(insertQ, e)
            exit()
        return sql.execute(selectQ)[0]['id']



#path to openmrs
path= "/Users/nasifimtiaz/openmrs"
os.chdir(path)
depfilename="dependency-check-report.csv"
files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]
for file in files:
    df= pd.read_csv(file, sep=',')
    
    if len(df) == 0:
        continue

    idmodule=getModuleId(df.iloc[0,0])
    df.insert(loc=0,column='idmodule',value=[idmodule]*len(df))
    df=redesignColumns(df)

    df['idpackage']=df.apply(lambda row: getPackageId(row.dependency, row.package),axis=1)
    
    df = df.astype(object).where(pd.notnull(df),'null')

    df['idvulnerability']=df.apply(lambda row: getVulnerabiltyId(row.idpackage, row.source, 
                    row.CVE, row.CWE, row.CPE,
                    row.description, row.vulnerability, row.CVSS2_severity,
                    row.CVSS2_score, row.CVSS3_severity, row.CVSS3_score ), axis=1)

    df['iddependency']=df.apply(lambda row: getDependencyId(row.idmodule, row.idpackage), axis=1) 
    
    df=df[['scandate','iddependency','idvulnerability','confidence']]
    
    sql.load_df('owasp',df)
    
    