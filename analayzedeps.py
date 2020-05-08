from parser import dependencyTree2dict
import os
import sql
from sql import execute, pd_read_sql
import pandas as pd
import csv

#path to openmrs
path= "/Users/nasifimtiaz/openmrs"
os.chdir(path)
depfilename="dep.txt"
doNotProcessModules=["openmrs"] 
files=(os.popen('find ./ -name "{}"'.format(depfilename)).read()).split("\n")[:-1]


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



for file in files:
    print(file)
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

        

    



