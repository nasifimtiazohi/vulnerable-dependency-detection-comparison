import subprocess, shlex
import os, sys
import json
import pandas as pd


def get_package_info(path):
    '''
    Given a repository path,
    returns the name and version of the npm package.
    '''
    os.chdir(path)
    
    #TODO: validate the path contains a package.json
    
    lines= subprocess.check_output(
        shlex.split('npm list --json --depth=0'),
        encoding='utf-8'
    )
    data=json.loads(lines)
    
    return data['name'], data['version']
    
      

def read_dependency_tree(hm, dependencyTree, depType, depth=1):
    for project in dependencyTree.keys():
        if 'peerMissing' in dependencyTree[project].keys():
            #optional dependencies
            continue
        
        version = dependencyTree[project]['version']
        if project not in hm:
            hm[project] = {version: {'depth':[depth], 'type':[depType]}}
        else:
            if version not in hm:
                hm[project][version]={'depth':[depth], 'type':[depType]}
            else:
                if depth not in hm[project][version]['depth']:
                    hm[project][version]['depth'].append(depth)
                if depType not in hm[project][version]['type']:
                    hm[project][version]['type'].append(depType)
                    
        if 'dependencies' in dependencyTree[project].keys():
            dependencies = dependencyTree[project]['dependencies']
            read_dependency_tree(hm, dependencies, depType, depth+1)
        

def dedupe_dependencies(hm):
    deps=[]
    
    for package in hm.keys():
        for version in hm[package].keys():
            if 'prod' in hm[package][version]['type']:
                depType='prod'
            else:
                depType='dev'
            
            depth = min(hm[package][version]['depth'])

            deps.append([package, version, depth, depType])
    
    return pd.DataFrame(deps, columns=['package', 'version', 'depth', 'scope'])
    

def getNpmList(path, type):
    os.chdir(path)
    
    try:
        lines= subprocess.check_output(
            shlex.split('npm list --json --{}'.format(type)),
            encoding='437'
        )
    except subprocess.CalledProcessError as e:
        # npm peer dependencies error can occur which 
        # which can be safely ignored
        lines=e.output
    
    return json.loads(lines)

def parse_dependency(path):
    '''
    Note that this process
    skips optional dependencies
    '''
    os.chdir(path)
    #os.system('rm -rf package-lock.json node_modules')
    os.system('npm install')
    
    hm={}
    
    data=getNpmList(path,'prod')
    if 'dependencies' in data.keys():
        read_dependency_tree(hm, data['dependencies'], 'prod') 
    
    data=getNpmList(path,'dev')
    if 'dependencies' in data.keys():
        read_dependency_tree(hm, data['dependencies'], 'dev') 
       
    df = dedupe_dependencies(hm)
    return df
if __name__=='__main__':
    # path='/Users/nasifimtiaz/Desktop/test'
    # package, version = get_package_info(path)
    # print(package, version)
    # hm= parse_dependency(path)
    # df= print(dedupe_dependencies(hm))
    # print(df)
    getNpmList('/Users/nasifimtiaz/openmrs/openmrs-module-idgen/owa','prod')
           
    