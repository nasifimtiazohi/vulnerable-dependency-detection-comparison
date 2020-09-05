import sys, os
sys.path.append('..')
import common, sql
import csv
import pandas as pd
import numpy as np
from datetime import datetime
import json 

toolId = common.getToolId('NPM Audit')

def readAdvisories(advisories):
    '''
    Get advisory list from npm audit
    retrieve corresponding vulnerabilityId 
    and returns the mapping
    '''
    hm={}
    for k in advisories.keys():
        data=advisories[k]
        vulnIds = []
        
        if 'cves' in data.keys() and len(data['cves'])>0:
            
        else:
            TODO


if __name__=='__main__':
    # q='''select * from repoDependencyFiles rDF
    #     join repository r on rDF.repositoryId = r.id
    #     where file like '%package.json';'''
    # results=sql.execute(q)
    # for item in results:
    #     repoId = item['repositoryId']
    #     path = '/Users/nasifimtiaz/openmrs/' + item['repoName'] + '/' + item['file']

    file = open('/Users/nasifimtiaz/openmrs/openmrs-module-idgen/owa/npmaudit.json','r')
    data = json.loads(file.read())
    
    count = 0
    ad=data['advisories']
    for k in ad.keys():
        findings=ad[k]['findings']
        count += len(findings)
    
    print(count)
    count=0
    
    ac = data['actions']
    
    for item in ac:
        count  += len(item['resolves'])
    
    print(count)    