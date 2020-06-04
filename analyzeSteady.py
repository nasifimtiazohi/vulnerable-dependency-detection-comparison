import os, sys
import sql, common
import json

hm={
    'vulnerableVersion' : 1,
    'unknown':2,
    'nonVulnerableVersion': 3,
    'noLibraryCodeAtAll':4,
    'nonVulnerableLibraryCode':5,
    'vulnerableLibraryCode':6            
    }
inv_hm = {v:k for k, v in hm.items()}

if __name__=='__main__':
    #Note: applications should already be scanned in the vulas VM and
    # generated reports should be synced to the machine where this code is running
    repos= common.getWatchedRepos()
    for path in repos:
        os.chdir(path)
        #read the root level target directory
        data= json.loads(open('target/vulas/report/vulas-report.json','r').read())['vulasReport']

        scandate= data['generatedAt']
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
        vulnerabilities=data['vulnerabilities']

        for vuln in vulnerabilities:
            #get package id
            package=vuln['filename']
            if not package.endswith('.jar') or 'jar' in package[:-4]:
                #second condition ensures single package
                raise Exception('package not jar',package)
            else:
                package=package[:-4]
                q='''select id
                    from package
                    where concat(artifact,'-',version) ='{}';
                    '''.format(package)
                packageId=sql.execute(q)[0]['id']
                dependencyId=common.getDependencyId(repoId,packageId)
            #get cve id
            if vuln['bug']['id'].startswith('CVE') and not 'CVE' in vuln['bug']['id'][3:]:
                #second condition ensures single CVE
                cve= vuln['bug']['id']
                if len(cve.split('-'))>3:
                    #some in vulas has extra addendums
                    print("check",cve)
                    cve='-'.join(x for x in cve.split('-')[:3])
                q='select id from vulnerability where CVE="{}"'.format(cve)
                results=sql.execute(q)
                if not results:
                    common.addFromRedhatApi(cve,packageId)
                    results=sql.execute(q)
                vulnerabilityId=results[0]['id']
            else:
                #process this vuln
                noncve=vuln['bug']['id']
                q='''insert into vulnerability values(null,
                        {},'vulas',null, '{}', null,null,null,null,null,null,null,null
                    );'''.format(packageId,noncve)
                sql.execute(q)
                q='select id from vulnerability where nonCVE="{}"'.format(noncve)
                vulnerabilityId=sql.execute(q)[0]['id']

            
            integrationTest=[]
            #DONE: write in a way so that first it can be run for only unit test
            #then again for integration test as well

            #check if already alert is pushed for the first three

            q='''select * from alert where dependencyId={}
                and vulnerabilityId={} and tool='steady' '''.format(dependencyId,vulnerabilityId)
            results = sql.execute(q)

            if not results:
                q='''insert into alert values (null,'{}',{},{},null,'steady');
                     '''.format(scandate, dependencyId, vulnerabilityId)
                sql.execute(q)

                q='''select * from alert where dependencyId={}
                and vulnerabilityId={} and tool='steady' '''.format(dependencyId,vulnerabilityId)
                results = sql.execute(q)
                alertId=results[0]['id']

                vulnerableVersion=[]
                staticAnalysis=[]
                unitTest=[]
                
                for module in vuln['modules']:
                    #get the static and dynamic analysis results into a separate table
                    vulnerableVersion.append(hm[module['containsVulnerableCode']])
                    staticAnalysis.append(hm[module['potentiallyExecutesVulnerableCode']])
                    unitTest.append(hm[module['actuallyExecutesVulnerableCode']])
                
                vv=max(vulnerableVersion)
                sa=max(staticAnalysis)
                ut=max(unitTest)

                #TODO: get alert ID
                q='''insert into steady values({},"{}", "{}","{}",null);
                 '''.format(alertId,inv_hm[vv],inv_hm[sa],inv_hm[ut])
                sql.execute(q)

                
            else:
                alertId=results[0]['id']
                integrationTest=[]
                for module in vuln['modules']:
                    integrationTest.append(hm[module['actuallyExecutesVulnerableCode']])
                it=max(integrationTest)
                q='''update alert set integrationTest='{}'
                     where alertId={} '''.format(inv_hm[it],alertId)
                print(q)
