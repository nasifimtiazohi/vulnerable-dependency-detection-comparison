import csv
import subprocess, shlex
import os, sys
sys.path.append('..')
import common, sql
toolId=common.getToolId('Contrast')
os.chdir('/Users/nasifimtiaz/Desktop/contrastReports')

files= subprocess.check_output(shlex.split('ls'), encoding='437').split('\n')[:-1]

for file in files:
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                print(f'Column names are {", ".join(row)}')
            else:
                library = row[0]
                assert library.endswith('.jar')
                library=library[:-len('.jar')]
                version=row[2]
                print(library,version)
                assert version.lower() in library.lower()
                library=library[:-len('-'+version)]
                q='select id from package where artifact=%s and version=%s'
                
                packageId=sql.execute(q,(library,version))[0]['id']
                
                language=row[1]
                
                grade=row[5]
                
                cveCount=row[7]
                
                usedClasses=row[11]
                totalClasses=row[10]

                insertQ='insert into contrast values(%s,%s,%s,%s,%s,%s)'
                sql.execute(insertQ,(packageId,language,grade,cveCount, totalClasses,usedClasses))
            
            line_count += 1
        
        assert line_count==2