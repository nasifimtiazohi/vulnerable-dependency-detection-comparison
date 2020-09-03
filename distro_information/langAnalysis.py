'''
/usr/local/lib/ruby/gems/2.7.0/bin/github-linguist --breakdown
'''
import os, sys
sys.path.append('..')
import common, sql
import subprocess, shlex

def language_breakdown(repoPath):
    os.chdir(repoPath)
    output=subprocess.check_output(
        ['github-linguist','--breakdown'],
        stderr=subprocess.STDOUT,
        encoding='437'
    )
    output=output.split('\n\n')[0]

    langs=output.split('\n')
    hm={}
    
    for lang in langs:
        lang=lang.replace(' ','')
        temp=lang.split('%')
        language, percentage = temp[1], temp[0]
        hm[language]=percentage
    
    return hm

def dependencyFileAnalysis(repoPath, langBreakdown):
    hm = {
        'Java': ['pom.xml'],
        'npm': ['package.json', 'package-lock.json'],
        'Ruby': ['Gemfile','gemspec','Gemfile.lock']
    }
    
    os.chdir(repoPath)
    
    depFiles=[]
    depFormats=[]
    
    for k in hm.keys():
        if k in langBreakdown.keys():
            for file in hm[k]:
                output=subprocess.check_output(
                    shlex.split('find . -name {}'.format(file)),
                    encoding='437'
                )
                if output:
                    output=output.split('\n')
                    depFiles+=output
                    depFormats.append(file)
    
    return depFormats, depFiles

def getRepoId(repo):
    q='select id from repository where repoName=%s'
    return sql.execute(q,(repo,))[0]['id']     

def addDependencyFiles(repoId, depFiles):
    q='insert into repoDependencyFiles values(%s,%s)'
    for file in depFiles:
        if file.startswith('./'):
            file=file[2:]
            sql.execute(q,(repoId,file))
              

if __name__== '__main__':
    repoPaths=common.getAllRepos()
    languages=[]
    formats={}
    for path in repoPaths:
        repo = path.split('/')[-1]
        repoId = getRepoId(repo)
        
        hm = language_breakdown(path)
        languages += list(hm.keys())
        
        depFormats, depFiles = dependencyFileAnalysis(path, hm)
        formats[repo]=depFormats
        addDependencyFiles(repoId, depFiles)
        
    
    print(maven,node,mixed)
        
