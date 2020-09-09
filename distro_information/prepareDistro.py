'''
Distro contains 44 projects.
43 are maven projects which are 
cloned and checked out through this script.
The other one, OWA module called sysadmin
is a npm package 
and not covered by maven SDK.
Therefore, it is cloned and processed individually.
'''
import sys, os
sys.path.append('..')
from lxml import etree as ET
import csv
import pandas as pd
import common, sql
import time
serverId='distro-2-10-0'
clonedRepos=[]


def readPom(file):
    pom = ET.parse(file)
    items= pom.find('//{http://maven.apache.org/POM/4.0.0}properties')
    items=items[1:]
    hm={}
    for idx, item in enumerate(items):
        if item.tag is ET.Comment:
            continue
    
        artifact= item.tag.replace('{http://maven.apache.org/POM/4.0.0}','').replace('Version','').strip().lower()
        hm[artifact]={}
        version=item.text.strip()
        if artifact == 'openmrs':
            group='org.openmrs'
            repoName='openmrs-core'
        elif artifact == 'event':
            group='org.openmrs'
            repoName='openmrs-module-'+artifact
        elif artifact == 'uitestframework':
            group='org.openmrs.contrib'
            repoName='openmrs-contrib-'+artifact
        elif artifact == 'sysadmin':
            group = 'npm'
            repoName = 'openmrs-owa-'+artifact
        else:
            group='org.openmrs.module'
            repoName='openmrs-module-'+artifact
        
        hm[artifact]['version']=version
        hm[artifact]['group']=group
        hm[artifact]['repo']=repoName

    return hm 

def cloneAndCheckoutVersion(artifact, data):
    os.chdir('/Users/nasifimtiaz/openmrs')
    version=data['version']
    group=data['group']
    repo=data['repo']

    command='''mvn openmrs-sdk:clone 
            -DserverId={} -DgroupId={} -DartifactId={}
            -DgithubUsername=nasifimtiazohi 
            -DgithubPassword={}'''.format(serverId, group ,artifact,password)
    command=command.replace('\n',' ')
    print(command)
    os.system(command)

    os.chdir('./'+repo)

    #get release tags
    release=[]
    tags=os.popen('git tag').read().split('\n')[:-1]
    for tag in tags:
        if tag.endswith(version):
            release.append(tag)
    
    assert len(release) == 1

    command='git checkout ' + release[0].strip()
    os.system(command)

    os.system('mvn openmrs-sdk:watch -DserverId={}'.format(serverId))

    time.sleep(3) #incase of api rate limits

def repoAlredyProcessed(repo) -> bool:
    query='''select * from repository where
            repoName="{}" '''.format(repo)
    results=sql.execute(query)
    if results:
        return True
    return False

def addRepo(group, artifact, version, repo):
    if repoAlredyProcessed(repo):
        return 
    sql.execute("insert into repository values(null,'{}','{}','{}','{}')".
            format(group, artifact, version,repo))


def addProjectsToDB(projects):
    for project in projects.keys():
        d= projects[project]
        addRepo(d['group'],project,d['version'],d['repo'])
        

def sdkSetup():
    projects = readPom('pom.xml')
    
    paths = common.getWatchedRepos()

    for path in paths:
        repo=path.split('/')[-1]
        clonedRepos.append(repo)
    

    for k in projects.keys():
        if projects[k]['repo'] in clonedRepos:
            continue
        if 'org.openmrs' not in projects[k]['group']:
            print(projects[k]['group'])
            continue

        cloneAndCheckoutVersion(k, projects[k])

def initial_setup():
    projects = readPom('pom.xml')
    
    addProjectsToDB(projects)
    
    paths = common.getWatchedRepos()

    for path in paths:
        repo=path.split('/')[-1]
        clonedRepos.append(repo)
    

    for k in projects.keys():
        if projects[k]['repo'] in clonedRepos:
            continue
        if 'org.openmrs' not in projects[k]['group']:
            continue

        cloneAndCheckoutVersion(k, projects[k])
        
def pushGitRepo(path):
    '''
    check if current head at required branch/release
    git stash changes
    push repo to my account
        with a changed name
    '''

def getRepoReleaseMapping():
    projects = readPom('/Users/nasifimtiaz/Desktop/vulnerable-dependency-detection-comparison/distro_information/pom.xml')
    hm={}
    
    for k  in projects.keys():
        repo = projects[k]['repo']
        release = projects[k]['version']
        hm[repo]=release
        
    assert len(projects) == len(hm)
    return hm

def check_heads(paths):
    repos=[]
    for path in paths:
        repos.append(path.split('/')[-1])
    
    hm=readPom('/Users/nasifimtiaz/Desktop/vulnerable-dependency-detection-comparison/pom.xml')

    def find_repo_key(repo):
        nonlocal hm
        for k in hm.keys():
            if hm[k]['repo']==repo:
                return k

    os.chdir('/Users/nasifimtiaz/openmrs')
    for repo in repos:
        os.chdir('./'+repo)
        output=os.popen('git branch').read()
        k=find_repo_key(repo)
        if hm[k]['version'] not in output:
            return False
        os.chdir('..')

    return True
    
if __name__=='__main__':
    password=os.environ['github_token']
    hm = getRepoReleaseMapping()
    paths= common.getAllRepos()
    print(hm,paths)
    
    