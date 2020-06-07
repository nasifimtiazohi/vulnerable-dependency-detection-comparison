#this script checks if all repos have heads at version for distro-2-10-0
#also generate the commit link to scan to send o source clear
#this script can be also used to run other scanning scripts to run on all repos
import common, sql
import os
import prepareDistro
import analyzeDeps
import analyzeOWASP
import analyzeVictim


def check_heads():
    paths = common.getWatchedRepos()
    repos=[]
    for path in paths:
        repos.append(path.split('/')[-1])
    
    hm=prepareDistro.readPom('/Users/nasifimtiaz/Desktop/vulnerable-dependency-detection-comparison/pom.xml')

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

def run_deps():
    paths = common.getWatchedRepos()
    for path in paths:
        print(path)
        assert path.startswith('/Users') #absolute path 
        analyzeDeps.addDependencies(path)


def run_OWASP():
    paths=common.getWatchedRepos()
    for path in paths:
        print(path)
        os.chdir(path)
        os.system('mvn org.owasp:dependency-check-maven:aggregate -Dformat=CSV')
        analyzeOWASP.process_alerts(path)

def run_victims():
    repos=common.getWatchedRepos()
    for path in repos:
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
        os.chdir(path)
        os.system('mvn com.redhat.victims.maven:security-versions:check')
        os.chdir(path+'/target')
        files=(os.popen("find . -type f -path */dependencies/* -name index.html").read()).split("\n")[:-1]
        for file in files:
            soup= BeautifulSoup(open(file).read(),'lxml')
            d=getVulns(soup.find_all('table')[0])
            for k in d.keys(): #each key is a module 
                insertVulns(repoId, d[k])


if __name__== '__main__':
    # assert check_heads()
    # run_deps()
    run_OWASP()