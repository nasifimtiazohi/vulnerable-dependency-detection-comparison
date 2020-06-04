import os, json
import common, sql

if __name__=='__main__':
    repos= common.getWatchedRepos()

    for path in repos:
        os.chdir(path)
        repo= path.split('/')[-1]
        repoId=common.getRepoId(repo)
        report= json.loads(os.popen('snyk test --json').read())
        for vuln in report['vulnerabilities']:
            group=vuln['mavenModuleName']['groupId']
            artifact=vuln['mavenModuleName']['artifactId']
            version=vuln['version']

            packageId = common.getPackageId(group,artifact,version)
            dependencyId = common.getDependencyId(repoId, packageId)

            cves=vuln['identifiers']['CVE']
            if cves:
                for cve in cves: 
                    q="select id from vulnerability where CVE='{}'".format(cve)
                    results=sql.execute(q)
                    if not results:
                        common.addFromNvdApi(cve,packageId)
                        q="select id from vulnerability where CVE='{}'".format(cve)
                        results=sql.execute(q)
                    
                    vulnerabilityId=results[0]['id']

                    q="insert into alert values(null,null,{},{},null,'snyk');".format(
                        str(dependencyId), str(vulnerabilityId))  
                    sql.execute(q)
            else:
                #process new vulnerabilty 
                noncve=vuln['id']
                source='snyk'
                description=vuln['description'].replace('"','').replace("'",'')
                vulnerability=vuln['title']
                CVSS3severity=vuln['severity']
                cwe=','.join(vuln['identifiers']['CWE'])
                selectQ='select id from vulnerability where nonCVE="{}";'.format(noncve)
                results=sql.execute(selectQ)
                if not results:
                    q='''insert into vulnerability values(null,
                        {},'snyk',null, '{}', '{}',null, '{}','{}',null,null,'{}',null
                    );'''.format(packageId,noncve,cwe,description,vulnerability,CVSS3severity)
                    sql.execute(q)
                    results=sql.execute(selectQ)

                vulnerabilityId=results[0]['id']

                q="insert into alert values(null,null,{},{},null,'snyk');".format(
                        str(dependencyId), str(vulnerabilityId))  
                sql.execute(q)

        