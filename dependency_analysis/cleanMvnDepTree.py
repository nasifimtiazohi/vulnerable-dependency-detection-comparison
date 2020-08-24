import os, sys
sys.path.append('..')
import common, sql

#getting all distinct java third-pary deps
q='''select *
from dependency d
join package p on d.packageId = p.id
where `group` not like %s
and `group` != 'javascript';'''
deps= sql.execute(q,('%openmrs%',))
print(len(deps))

for dep in deps:
    repoId = dep['repositoryId']
    packageId = dep['packageId']
    dependencyId = dep['id']
    q='''select *
        from mavenDependencyTree mDT
        join package p on mDT.packageId = p.id
        where repositoryId=%s
        and packageId=%s '''
    results= sql.execute(q, (repoId,packageId))
    
    if len(results) == 1:
        depth = item['depth']
        scope = item['scope']
    else:
        #pick one
        scopes = []
        depths = []
        for item in results:
            scope=item['scope']
            if 'compile' in scope:
                scopes.append('compile')
            elif 'test' in scope:
                scopes.append('test')
            elif 'provided' in scope:
                scopes.append('provided')
            elif 'runtime' in scope:
                scopes.append('runtime')
            
            depths.append(item['depth'])
        
        depth = min(depths)        
        scope=None
        if 'provided' in scopes:
                scope='provided'
        elif 'compile' in scopes:
                scope='compile'
        elif 'runtime' in scopes:
                scope='runtime'
        elif 'test' in scopes:
                scope='test'
    
    q='insert into derivedMavenDependencyTree values (%s,%s,%s)'
    sql.execute(q,(dependencyId,depth,scope))
        
    
    