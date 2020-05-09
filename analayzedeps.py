from parser import dependencyTree2dict
import os
import sql
from sql import execute, pd_read_sql
import pandas as pd
import csv

doNotProcessModules=["openmrs"] 

def moduleAlredyProcessed(group, artifact, version) -> bool:
    query='''select * from modules where
            `group`='{}' and artifact='{}' and version ='{}'
                     '''.format(group, artifact, version)
    results=execute(query)
    if results:
        return True
    return False

def addModule(group, artifact, version) -> int:
    execute("insert into modules values(null,'{}','{}','{}')".format(group, artifact, version))
    query='''select * from modules where
            `group`='{}' and artifact='{}' and version ='{}'
                     '''.format(group, artifact, version)
    results=execute(query)
    return results[0]['id']


def addDependencies():
    #path to openmrs
    path= "/Users/nasifimtiaz/openmrs"
    os.chdir(path)
    depfilename="dep.txt"
    files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]
    for file in files:
        data=dependencyTree2dict(file)
        group, artifact, version=data['project'].split(':')
        if not moduleAlredyProcessed(group, artifact, version) and artifact not in doNotProcessModules:
            id=addModule(group, artifact, version)
            data=data['dependencies']
            if not data:
                #zero dependencies
                continue
            data['idmodules']= [id] * len(data['artifact'])
            df=pd.DataFrame(data)
            sql.load_df('dependencyTree',df)

        
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
        


    

if __name__=='__main__':
    analyzeDependencies()
    



