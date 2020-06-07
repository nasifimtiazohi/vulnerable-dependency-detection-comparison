import common
from github import Github
token=os.environ['github_token']

def enable_dependency_alerts(owner, repo):
    g=Github(token)
    repo=g.get_repo(owner+'/'+repo)
    #enable vulnerability alert if not 
    if not repo.get_vulnerability_alert():
        repo.enable_vulnerability_alert()

paths=common.getWatchedRepos()
for path in paths:
    print(path)
    repo= path.split('/')[-1]
    owner='nasifimtiazohi'
    enable_dependency_alerts(owner,repo)