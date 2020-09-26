import os, sys
sys.path.append('../..')
import common, sql
import distro_information.prepareDistro as distro
import subprocess, shlex
import re
import csv

def github_urls():
    repoRelaseMapping = distro.getRepoReleaseMapping()
    urls={}
    for repo in repoRelaseMapping.keys():
        release = repoRelaseMapping[repo]
        url='https://github.com/nasifimtiazohi/{}-{}'.format(repo,release)
        urls[common.getRepoId(repo)]=url
    return urls

def get_packagejson_files():
    q='''select * from repoDependencyFiles rDF
            join repository r on rDF.repositoryId = r.id
            where file like %s;'''
    results = sql.execute(q,('%package.json%'))
    
    hm={} 
    
    for item in results:
        hm[item['repositoryId']]=item['file']
    
    return hm   
    
    
if __name__=='__main__':
    urls = github_urls()
    npm_files=get_packagejson_files()
    print(npm_files)
    
    with open('repo_urls.csv', mode='w') as file:
        file = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        
        file.writerow(['github_url', 'maven build file', 'npm build file'])
        for repoId in urls.keys():
            print(repoId)
            url= urls[repoId]
            mavenFile = npmFile = ''
            if repoId != 44:
                mavenFile = './pom.xml'
            if repoId in npm_files:
                print("what?")
                npmFile = npm_files[repoId]
            
            file.writerow([url,mavenFile, npmFile])
        
    