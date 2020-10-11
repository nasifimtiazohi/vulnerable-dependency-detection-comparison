import os, sys
sys.path.append('../..')
from gh_graphql import getDependencyAlerts
import distro_information.prepareDistro as distro
import common, sql
import time, dateutil.parser as dt 
from datetime import datetime
toolId=common.getToolId('WhiteSource')
token=os.environ['github_token']
from github import Github
import json
import markdown as md
from bs4 import BeautifulSoup as bs

def getPackageId(library,eco):
    q='''select * from package
        where concat(artifact,'-',version) = %s'''
    results = sql.execute(q,(library,))
    if not results:
        print("not in db",library, eco)
        temp = library.split('-')
        version=temp[-1]
        temp=temp[:-1]
        artifact ='-'.join(temp)
        return common.getPackageId(eco, artifact, version, eco, True )
    else:
        return results[0]['id']

def acceptWhiteSourcePR(name):
    print('accepting for', name)
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    issues = repo.get_issues()
    for issue in issues:
        if issue.title == 'Configure WhiteSource Bolt for GitHub':
            pr = issue.as_pull_request()
            if not pr.merged:
                pr.merge()


def addWhiteSourceVulnerability(id, publishDate, description, cvss):
    cvss= cvss.find_all('b')
    assert len(cvss)==1
    score = float(cvss[0].text)

    insertQ='insert into vulnerability values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
    try:
        sql.execute(insertQ,(None, 'WhiteSource', 
                            None, id, 
                            publishDate, description, 
                            None, None, score, None))
    except sql.pymysql.IntegrityError as error:
        if error.args[0] == sql.PYMYSQL_DUPLICATE_ERROR:
            print(id, ' already exists')
        else:
            raise Exception(str(error))
    

def process_vuln(vuln,cvss):
    headers = vuln.find_all('p')
    publishDate=url=description=None
    for header in headers:
        if header.text.strip() == '':
            continue
        if 'Publish Date' in header.text:
            publishDate= header.text
        elif 'URL:' in header.text:
            url=  header.text
        else:
            description = header.text
    
    assert publishDate and url and description
    
    url=url.strip()
    publishDate=publishDate.strip()

    publishDate = publishDate[:-len(url)]
    publishDate = publishDate[len('Publish Date:')+1:].strip()
    publishDate = dt.parse(publishDate)
    
    id= url[len('URL:'):].strip()
    
    wsid=True
    if 'CVE' in id:
        vulnId = common.getVulnerabilityId(id, None)
        if vulnId > 0:
            wsid =False
            
    if wsid:
        vulnId = common.getVulnerabilityId(None, id)
        if vulnId <= 0:
            vulnId = addWhiteSourceVulnerability(id, publishDate, description, cvss)
            vulnId = common.getVulnerabilityId(None, id)
    
    return vulnId

def getLibraryId(library):
    if library.endswith('.jar'):
        #process maven package
        library=library[:-len('.jar')]
        eco = 'maven'
    elif library.endswith('tgz'):
        #process npm package
        library=library[:-len('.tgz')]
        eco='npm'
    elif library.endswith('.js'):
        library=library[:-len('.js')]
        eco='javascript'
        if 'jquery-ui' in library:
           pass 
        elif library.endswith('.min'):
            library=library[:-len('.min')]
            try:
                artifact, version = library.split('-')
                library = artifact + '.min-' +version
            except:
                raise Exception(library)
        
    elif library.endswith('.gem') or 'bundler' in library or 'openmrs' in library or library=='sensible-cinemasensible-cinema-0.35.0':
        #ruby library do nothing
        return None,None
    else:
        #hardcoding edge cases
        if library=='node-sass3.1.0':
            library='node-sass-3.1.0'
            eco='npm'
        elif 'swagger' in library or 'angular' in library:
            eco='javascript'
        else:
            raise Exception('check ', library)
    
    packageId = getPackageId(library, eco)
    if eco!='npm':
        eco='maven'
    return packageId, eco
    
def process_libraries(libraries):
    libraries = libraries.find_all('b')
    ids=[]
    for library in libraries:
        library = library.text
        id, eco = getLibraryId(library)
        if id:
            ids.append((id,eco))
    return ids

def process_alert(s, repoId):
    html = md.markdown(s)
    soup = bs(html, 'html.parser')
    headers = soup.find_all('details')
    libraries, vuln, cvss, fix = [None]*4 
    for header in headers:
        if 'Vulnerable Librar' in header.text:
            libraries = header
        elif 'Vulnerability Details'  in header.text:
            vuln=header
        elif 'CVSS' in header.text:
            cvss=header
        elif 'Suggested Fix' in header.text:
                fix = header
    
    assert libraries and vuln and cvss
    
    vulnId = process_vuln(vuln,cvss)
    
    libraryIds = process_libraries(libraries)
        
    for id, eco in libraryIds:
        dependencyId = common.getDependencyId(repoId,id,toolId,True)
        if eco == 'maven':
            try:
                insertQ = 'insert into mavenAlert values(%s,%s,%s,%s,%s,%s,%s,%s)'
                sql.execute(insertQ,(None,None,dependencyId,vulnId,toolId,None,None,1))
            except:
                continue
        elif eco == 'npm':
            try:
                insertQ = 'insert into npmAlert values(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                sql.execute(insertQ,(None,None,dependencyId,vulnId,None,toolId,None,None,1))
            except:
                continue
            
    
    
            
    
    
def get_whitesource_issues(name, repoId):
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    issues = repo.get_issues()
    for issue in issues:
        if issue.user.login != 'whitesource-bolt-for-github[bot]':
            continue
        process_alert(issue.body, repoId)
    
def acceptRenovatePR(name):
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    issues = repo.get_issues()
    for issue in issues:
        if issue.user.login != 'renovate[bot]':
            continue
        if issue.title == 'Configure Renovate':
            pr = issue.as_pull_request()
            if not pr.merged:
                pr.merge()


def readRenvatePr(name, repoId):
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    issues = repo.get_issues()
    for issue in issues:
        if issue.user.login != 'renovate[bot]':
            continue
        if 'Update dependency' not in issue.title:
            continue
        html = md.markdown(issue.body)
        soup = bs(html, 'html.parser')
        p = str(soup.find_all('p')[1])
        p = p.split('|')
        changeType = (p[-3])
        
        q='insert into renovate values(%s,%s)'
        sql.execute(q,(repoId, changeType))

def getChangeType(prior, fixed):
    prior= prior.split('.')
    fixed =fixed.split('.')
    
    if int(fixed[0]) > int(prior[0]):
        return 'major'
    elif int(fixed[1]) > int(prior[1]):
        return 'minor'
    else:
        return 'patch'

def readDependabotPR(name, repoId):
    g=Github(token)
    user = g.get_user()
    repo = user.get_repo(name)
    issues = repo.get_issues()
    for issue in issues:
        if issue.user.login != 'dependabot[bot]':
            continue
        if 'Bump' not in issue.title:
            continue
        body = issue.body.split('\n')[0]
        print(body)
        body=body.strip()
        body=body.split(' ')
        prior = body[-3]
        fixed=body[-1]
        changeType=getChangeType(prior,fixed)
        
        q='insert into dependabotPR values(%s,%s)'
        sql.execute(q,(repoId, changeType))        
if __name__=='__main__':
    repoRelaseMapping = distro.getRepoReleaseMapping()
    
    for repo in repoRelaseMapping.keys():
        repoId=common.getRepoId(repo)
        githubReponame = repo + '-' + repoRelaseMapping[repo]
        print(githubReponame)
        get_whitesource_issues(githubReponame,repoId)
        #readDependabotPR(githubReponame, repoId)