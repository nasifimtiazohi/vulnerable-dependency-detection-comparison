import os, sys
sys.path.append('../..')
from gh_graphql import getDependencyAlerts
import common, sql
import time, dateutil.parser as dt 
from datetime import datetime

token=os.environ['github_token']



def processAlerts(owner, repo):
    print(repo)
    repoId=common.getRepoId(repo)
    alerts=getDependencyAlerts(owner, repo)
    print(alerts)
    exit()

    #process alerts
    for alert in alerts:
        package= alert['securityVulnerability']['package']['name'].split(':')
        group=package[0]
        artifact=package[1]
        query='''select *
            from dependency d
            join package p
            on d.packageId=p.id
            where d.repositoryId={}
            and p.`group`='{}'
            and p.artifact='{}';'''.format(repoId, group, artifact)
        iddependency = sql.execute(query)[0]['id'] #take the first one in case of multiple versions present
        #Note: GitHub does not present version within its alert
        
        temp=alert['securityAdvisory']['identifiers'] 
        cve=None
        for t in temp:
            if t['type']=='CVE':
                cve=t['value']
                break
        if not cve:
            raise Exception('outside cve found')
        q="select id from vulnerability where CVE='{}'".format(cve)

        try:
            idvulnerability=sql.execute(q)[0]['id']
        except:
            raise Exception('need to insert CVE into database')
        #TODO: modify to regard for severity and cve insertion
        #NOTE: GitHub has its own severity rating
        q="insert into alert values(null,null,{},{},null,'github');".format(
            str(iddependency), str(idvulnerability))      

        try:
            sql.execute(q)  
        except Exception as e:
            print(e)
    time.sleep(3)


if __name__=='__main__':
    paths = common.getAllRepos()
    for path in paths:
        repo = path.split('/')[-1]
        repoId= common.getRepoId(repo)
        if repoId != 8:
            continue
        processAlerts('nasifimtiazohi',repo)
        