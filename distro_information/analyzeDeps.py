from parser import dependencyTree2dict
import os
import common, sql
from common import getPackageId
from sql import execute, pd_read_sql
import pandas as pd
import csv
import numpy as np


def repoAlredyProcessed(repo) -> bool:
    query='''select * from repository where
            repoName="{}" '''.format(repo)
    results=execute(query)
    if results:
        return True
    return False

def addRepo(group, artifact, version, repo) -> int:
    execute("insert into repository values(null,'{}','{}','{}','{}')".format(group, artifact, version,repo))
    query='''select * from repository where
            `group`='{}' and artifact='{}' and version ='{}'
            and repoName='{}'
            '''.format(group, artifact, version, repo)
    results=execute(query)
    return results[0]['id']




def addDependencies(path):
    depfilename="dep.txt"
    os.chdir(path)
    os.system('mvn dependency:tree -DoutputFile={}'.format(depfilename))
    repo=path.split('/')[-1]
    files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]
    data=dependencyTree2dict('./'+depfilename)
    group, artifact, version=data['project'].split(':')
    if not repoAlredyProcessed(repo):
        repoId=addRepo(group, artifact, version, repo)
    else:
        return 
    dependencyDf= pd.DataFrame(columns=['repositoryId','packageId'])
    for file in files:
        data=dependencyTree2dict(file)
        module=data['project'].split(':')[1]
        data=data['dependencies']
        if not data:
            #zero dependencies
            continue
        data['repositoryId']= [repoId]*len(data['artifact'])
        data['module']= [module]*len(data['artifact'])
        df=pd.DataFrame(data)
        df['packageId']=df.apply(lambda row: getPackageId(row.group, row.artifact, row.version, 'maven'), axis=1)
        df.drop(['group','artifact','version'], axis=1, inplace=True)
        sql.load_df('dependencyTree',df)
        df=df[['repositoryId','packageId']]
        dependencyDf = dependencyDf.append(df, ignore_index=True)

    dependencyDf = dependencyDf.drop_duplicates(subset='packageId',keep='last')
    dependencyDf['id']=[np.nan]*len(dependencyDf)
    sql.load_df('dependency',dependencyDf)        

        
def analyzeDependencies():
    df=pd_read_sql('''select m.artifact as module, dt.*
                    from modules m
                    join dependencyTree dt
                    on m.id=dt.idmodules;''')
    gb=df.groupby('module')
    table=[]
    for k, gp in gb:
        total=len(gp)
        compile= len(gp[gp.scope=='compile'])
        test = len(gp[gp.scope=='test'])
        others = total - compile - test
        direct = len(gp[gp.depth == 1])
        transitive = total - direct
        median = int(gp.depth.median())
        max = gp.depth.max()
        temp=[k,compile,test,others,direct,transitive,median,max]
        table.append('&'.join(str(x) for x in temp) + '\\\\')
    
    for t in table:
        print(t)
        

def check():
    #rerun dependency analysis and check if all was done right
    paths=common.getWatchedRepos()
    for path in paths:
        repo=path.split('/')[-1]
        repoId=common.getRepoId(repo)
    

if __name__=='__main__':
    repos=common.getWatchedRepos()
    for path in repos:
        repo=path.split("/")[-1]
        if not repoAlredyProcessed(repo):
            addDependencies(path)

    



