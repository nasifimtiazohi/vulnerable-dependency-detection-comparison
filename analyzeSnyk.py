import os, json
import common, sql

def getDependencyId(repo, group,artifact):
    query='''select dT.id
                from modules m
                join dependencyTree dT
                on m.id=dT.idmodule
                join packages p on
                    p.id = dT.idpackage
                where m.repository='{}'
                and p.`group`='{}'
                and p.artifact='{}';'''.format(repo, group, artifact)
    return sql.execute(query)[0]['id']

if __name__=='__main__':
    repos= common.getWatchedRepos()

    for path in repos:
        os.chdir(path)
        repo= path.split('/')[-1]
        report= json.loads(os.popen('snyk test --json').read())
        for vuln in report['vulnerabilities']:
            group=vuln['mavenModuleName']['groupId']
            artifact=vuln['mavenModuleName']['artifactId']
            version=vuln['version']
            iddependency= getDependencyId(repo,group,artifact)
            idpackage=common.getPackageId(group,artifact,version)
            cves=vuln['identifiers']['CVE']
            if cves:
                
                for cve in cves: 
                    q="select id from vulnerabilities where CVE='{}'".format(cve)
                    results=sql.execute(q)
                    if not results:
                        common.addFromNvdApi(cve,idpackage)
                        q="select id from vulnerabilities where CVE='{}'".format(cve)
                        results=sql.execute(q)
                    
                    idvulnerability=results[0]['id']

                    q="insert into alerts values(null,{},{},null,'snyk');".format(
                        str(iddependency), str(idvulnerability))  
                    sql.execute(q)
            else:
                #process new vulnerabilty 
                noncve=vuln['id']
                source='snyk'
                description=vuln['description'].replace('"','').replace("'",'')
                vulnerability=vuln['title']
                CVSS3severity=vuln['severity']
                cwe=','.join(vuln['identifiers']['CWE'])
                selectQ='select id from vulnerabilities where nonCVE="{}";'.format(noncve)
                results=sql.execute(selectQ)
                if not results:
                    q='''insert into vulnerabilities values(null,
                        {},'snyk',null, '{}', '{}',null, '{}','{}',null,null,'{}',null
                    );'''.format(idpackage,noncve,cwe,description,vulnerability,CVSS3severity)
                    sql.execute(q)
                    results=sql.execute(selectQ)

                idvulnerability=results[0]['id']

                q="insert into alerts values(null,{},{},null,'snyk');".format(
                        str(iddependency), str(idvulnerability))  
                sql.execute(q)

        