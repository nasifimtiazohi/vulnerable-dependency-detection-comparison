import analyzeGitHub, common

paths=common.getWatchedRepos()
for path in paths:
    print(path)
    repo= path.split('/')[-1]
    owner='nasifimtiazohi'
    analyzeGitHub.enable_dependency_alerts(owner,repo)