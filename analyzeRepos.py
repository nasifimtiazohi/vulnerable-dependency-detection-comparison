#this script checks if all repos have heads at version for distro-2-10-0
#also generate the commit link to scan to send o source clear
#this script can be also used to run other scanning scripts to run on all repos
import common, sql
import os
import prepareDistro
import analyzeDeps
import analyzeOWASP
import analyzeVictim
import analyzeGitHub
import analyzeSnyk


def check_heads(paths):
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

def run_deps(paths):
    for path in paths:
        print(path)
        assert path.startswith('/Users') #absolute path 
        analyzeDeps.addDependencies(path)


def run_OWASP(paths):
    for path in paths:
        analyzeOWASP.process_alerts(path)

def run_victims(paths):
    for path in paths:
        analyzeVictim.scanAndProcess(path)

def run_snyk(paths):
    for path in paths:
        analyzeSnyk.scanAndProcess(path)
    
def run_github(paths):
    for path in paths:
        repo=path.split('/')[-1]
        owner='nasifimtiazohi'
        analyzeGitHub.processAlerts(owner, repo)

if __name__== '__main__':
    paths = common.getWatchedRepos()
    # assert check_heads()
    # run_deps()
    #run_OWASP()
    # run_victims()
    run_github(paths)
    #run_snyk(paths)
        

