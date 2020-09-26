import os, sys
sys.path.append('../..')
import common, sql
import distro_information.prepareDistro as distro
import subprocess, shlex
import re
from github import Github

token=os.environ['github_token']

def copyFilesOfGitRepo(src, dest):
    '''
    src is the git repo path
    dest is the path where we want to copy the folder
    '''
    os.system('rsync -r --exclude .git {} {}'.format(src, dest))


def resetAndCheckHead(path, release):
    os.chdir(path)
    
    subprocess.check_output(shlex.split('git reset --hard HEAD'))
    subprocess.check_output(shlex.split('git clean -dfx'))
    
    lines= subprocess.check_output(shlex.split('git branch'), encoding='437').split('\n')
    line = lines[0]
    assert re.search("^\* \(HEAD detached at .*\)$", line)
    line=line[len('* (HEAD detached at '):-len(')')]
    print (line)
    assert release in line


def createGithubRepo(name):
    g=Github(token)
    user = g.get_user()
    repo = user.create_repo(name)
    if not repo.get_vulnerability_alert():
        print("enabling dependabot alert for ", name)
        print(repo.enable_vulnerability_alert())

def repositorySetup(path,githubReponame):
    os.chdir(path)
    
    commands = [
        'git init',
        'git add .',
        'git commit -m "setting up specific release repo"',
        'git branch -M master',
        'git remote add origin https://github.com/nasifimtiazohi/{}.git'.format(githubReponame),
        'git push -u origin master'
    ]
    
    for c in commands:
        os.system(c)

def enable_dependency_alerts(owner, repo):
    g=Github(token)
    repo=g.get_repo(owner+'/'+repo)
    #enable vulnerability alert if not 
    if not repo.get_vulnerability_alert():
        print("enabling dependabot alert. (2) for ", repo)
        repo.enable_vulnerability_alert()

def deleteRepo(name):
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    repo.delete()
    
if __name__=='__main__':
    repoRelaseMapping = distro.getRepoReleaseMapping()
    paths= common.getAllRepos()
    dest = '/Users/nasifimtiaz/Desktop/openmrsCopyRepos/'
    
    for path in paths:
        repo = path.split('/')[-1]
        release = repoRelaseMapping[repo]
        resetAndCheckHead(path, release)
        # githubReponame= repo+'-'+release
        # print(githubReponame)
        
        # copyFilesOfGitRepo(path, dest)
        # createGithubRepo(githubReponame)
        # repositorySetup(dest+repo+'/', githubReponame)
        # enable_dependency_alerts('nasifimtiazohi',githubReponame)
