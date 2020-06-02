import os
from github import Github
from gh_graphql import getDependencyAlerts
import common
import sql

token=os.environ['github_token']



if __name__=='__main__':
    g=Github(token)
    owner='nasifimtiazohi'

    repos=common.getWatchedRepos()
    
    for path in repos:
        repoName= path.split('/')[-1]
        repoId=common.getRepoId(repoName)

        repo=g.get_repo(owner+'/'+repoName)

        #enable vulnerability alert if not 
        if not repo.get_vulnerability_alert():
            repo.enable_vulnerability_alert()
        
        alerts=getDependencyAlerts(owner, repoName)

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
            q="insert into alert values(null,{},{},null,'github');".format(
                str(iddependency), str(idvulnerability))      

            sql.execute(q)  


    
        