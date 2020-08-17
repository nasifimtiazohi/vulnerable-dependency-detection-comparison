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
        'JavaScript': ['package.json', 'package-lock.json'],
        'Ruby': ['Gemfile','gemspec','Gemfile.lock']
    }
    
    os.chdir(repoPath)
    
    print(os.getcwd())
    
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
            

if __name__== '__main__':
    language_breakdown('/Users/nasifimtiaz/openmrs/openmrs-module-coreapps')
    repoPaths=common.getAllRepos()
    languages=[]
    for path in repoPaths:
        hm = language_breakdown(path)
        languages += list(hm.keys())
        depFormats, depFiles = dependencyFileAnalysis(path, hm)
        print(path, depFormats)
    
    print(set(languages))