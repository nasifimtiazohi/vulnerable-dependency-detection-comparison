import os, sys
import sql, common
import json

if __name__=='__main__':
    repos= common.getWatchedRepos()
    for path in repos:
        os.chdir(path)
        #read the root level target directory
        data= json.loads(open('target/vulas/report/vulas-report.json','r').read())['vulasReport']

        scandate= data['generatedAt']
        repo=path.split('/')[-1]
        vulnerabilities=data['vulnerabilities']

        for vuln in vulnerabilities:
            #get package id
            package=vuln['filename']
            if not package.endswith('.jar'):
                raise Exception('package not jar',package)
            else:
                package=package[:-4]
                q='''select id
                        from packages
                        where concat(artifact,'-',version) ='{}';
                        '''.format(package)
                idpackage=sql.execute(q)[0]['id']
            #get cve id
            if vuln['bug']['id'].startswith('CVE'):
                cve= vuln['bug']['id']
                if len(cve.split('-'))>3:
                    #some in vulas has extra addendums
                    cve='-'.join(x for x in cve.split('-')[:3])
                q='select id from vulnerabilities where CVE="{}"'.format(cve)
                results=sql.execute(q)
                if not results:
                    common.addFromRedhatApi(cve,idpackage)
                    results=sql.execute(q)
                idvulnerability=results[0]['id']
            else:
                #process this vuln
                noncve=vuln['bug']['id']
                q='''insert into vulnerabilities values(null,
                        {},'vulas',null, '{}', null,null,null,null,null,null,null,null
                    );'''.format(idpackage,noncve)
                sql.execute(q)
                q='select id from vulnerabilities where nonCVE="{}"'.format(noncve)
                idvulnerability=sql.execute(q)[0]['id']
            for module in vuln['modules']:
                module=module['artifactId']
                idmodule=common.getModuleId(module)
                iddependency=common.getDependencyId(idmodule, idpackage)
                q="insert into alerts values(null,{},{},null,'vulas');".format(
                        str(iddependency), str(idvulnerability))  
                #print(q)
                sql.execute(q)