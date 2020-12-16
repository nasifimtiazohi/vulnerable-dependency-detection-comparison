import sys, os
sys.path.append('..')
import common, sql

q='''select distinct sourceId from vulnerability v
    where cveId is null;'''
results = sql.execute(q)

for item in results:
    sourceId = item['sourceId']
    
    q='''select *
        from vulnerability
        where sourceId=%s'''
    vulnIds = sql.execute(q,(sourceId,))
    
    if len(vulnIds) == 1:
        continue
    
    ids = []
    for vuln in vulnIds:
        ids.append(vuln['id'])
    
    q='''select distinct vulnerabilityId from npmAlert
        where vulnerabilityId in ({})'''.format(','.join(str(x) for x in ids))
    mainId = sql.execute(q)[0]['vulnerabilityId']
    
    ids.remove(mainId)
    
    q='delete from vulnerability where id in ({})'.format(','.join(str(x) for x in ids))
    sql.execute(q)
    
    