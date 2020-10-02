import os, sys
sys.path.append('..')
import sql, common

q='''select distinct concat(source,description) description from
(select distinct v.*
from mavenAlert mA
join vulnerability v on mA.vulnerabilityId = v.id
where toolId=4 and cveId is null
union
select distinct v.*
from npmAlert mA
join vulnerability v on mA.vulnerabilityId = v.id
where toolId=4 and cveId is null
order by description) as sub;'''
results = sql.execute(q)

for item in results:
    #get all the vuln_ids
    desc = item['description']
    q='''select id from vulnerability where concat(source,description) = %s
        and id in 
                (select distinct vulnerabilityId
                from mavenAlert
                union
                select distinct vulnerabilityId
                from npmAlert)'''
    ids=sql.execute(q, (desc,))
    if len(ids)==1:
        continue
    
    temp = []
    for id in ids:
        temp.append(id['id'])
    ids=temp
    
    assert len(ids) >1
    mainId=ids[0]
    replaceIds = ids[1:]
    print(mainId, replaceIds)
    
    #update vulnId in 
    q='''update mavenAlert
        set vulnerabilityId={}
        where vulnerabilityId in ({})'''.format(mainId,','.join(str(x) for x in replaceIds))
    sql.execute(q)
    
    #update vulnId in 
    q='''update npmAlert
        set vulnerabilityId={}
        where vulnerabilityId in ({})'''.format(mainId,','.join(str(x) for x in replaceIds))
    sql.execute(q) 
    
    for id in replaceIds:
        q='insert into owaspDuplicateNonCVEs values(%s,%s);'
        sql.execute(q,(mainId, id))