import os, sys
sys.path.append('..')
from parser import dependencyTree2Dict
import common, sql
from common import getPackageId
from sql import execute, pd_read_sql
import pandas as pd
import csv
import numpy as np
import subprocess, shlex 
import npmDepTreeParser as ndt


def addMavenDependencies(repoId, path):
    #generate maven dependency file 
    depfilename="dep.txt"
    os.chdir(path)
    os.system('mvn dependency:tree -DoutputFile={}'.format(depfilename))
    
    #read maven dependency file through dependencyTree2dict 
    files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]
    data=dependencyTree2Dict('./'+depfilename)
    group, artifact, version=data['project'].split(':')
    
    #a dataframe to just hold dependencies (repo & package)
    dependencyDf= pd.DataFrame(columns=['repositoryId','packageId'])
    
    #read dependency files to get tree data for each
    for file in files:
        data=dependencyTree2Dict(file)
        module=data['project'].split(':')[1]
        data=data['dependencies']
        if not data:
            #zero dependencies
            continue
        data['repositoryId']= [repoId]*len(data['artifact'])
        data['module']= [module]*len(data['artifact'])
        df=pd.DataFrame(data)
        df['packageId']=df.apply(lambda row: 
            getPackageId(row.group, row.artifact, row.version, 'maven'), axis=1)
        df.drop(['group','artifact','version'], axis=1, inplace=True)
        sql.load_df('mavenDependencyTree',df)
        df=df[['repositoryId','packageId']]
        dependencyDf = dependencyDf.append(df, ignore_index=True)

    dependencyDf = dependencyDf.drop_duplicates(subset='packageId',keep='last')
    dependencyDf['id']=[np.nan]*len(dependencyDf)
    sql.load_df('dependency',dependencyDf)        


def addNodeDependencies(repoId, path):
    df = ndt.parse_dependency(path)
    if df.empty:
        return
    
    df['packageId']=df.apply(lambda row:
        getPackageId('npm', row.package, row.version, 'npm'), axis=1)
    df.drop(['package','version'], axis=1, inplace=True)
    df['repositoryId']=[repoId]*len(df)
    sql.load_df('npmDependencyTree',df)
    
    df.drop(['depth','scope'], axis=1, inplace=True)
    df['id']=[np.nan]*len(df)
    sql.load_df('dependency',df)
    



def addDepndencies():
    repos= common.getNpmPackageRepos()
    sql.execute('truncate table npmDependencyTree')
    for repoId in repos:
        path = repos[repoId]
        print(repoId,path)
        addNodeDependencies(repoId,path)
    
    repos=common.getWatchedRepos()
    for path in repos:
        repo=path.split("/")[-1]
        repoId = common.getRepoId(repo)
        addMavenDependencies(repoId, path)

if __name__=='__main__':
    addDepndencies()

    



