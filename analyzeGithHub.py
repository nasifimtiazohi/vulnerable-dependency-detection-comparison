import os
from github import Github
from gh_graphql import getDependencyAlerts
import common
import sql

token=os.environ['token']

def getWatchedRepos():
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
                temp=line.split(' ')[-1]
                temp=temp.split('/')[-1]
                repos.append('nasifimtiazohi/'+temp)
    return repos

if __name__=='__main__':
    g=Github(token)


    repos=getWatchedRepos()
    
    for repo in repos:
        name=repo
        repo=g.get_repo(repo)

        #enable vulnerability alert if not 
        if not repo.get_vulnerability_alert():
            repo.enable_vulnerability_alert()
        
        name=name.split('/')
        owner=name[0]
        name= name[1]
        alerts=getDependencyAlerts(owner, name)

        #process alerts
        for alert in alerts:
            package= alert['securityVulnerability']['package']['name'].split(':')
            group=package[0]
            artifact=package[1]
            query='''select dT.id
                from modules m
                join dependencyTree dT
                on m.id=dT.idmodule
                join packages p on
                    p.id = dT.idpackage
                where m.repository='{}'
                and p.`group`='{}'
                and p.artifact='{}';'''.format(name, group, artifact)
            iddependency = sql.execute(query)[0]['id']
            
            temp=alert['securityAdvisory']['identifiers'] 
            cve=None
            for t in temp:
                if t['type']=='CVE':
                    cve=t['value']
                    break
            if not cve:
                raise Exception('outside cve found')
            q="select id from vulnerabilities where CVE='{}'".format(cve)

            idvulnerability=sql.execute(q)[0]['id']

            q="insert into alerts values(null,{},{},null,'github');".format(
                str(iddependency), str(idvulnerability))      

            sql.execute(q)  


    
        