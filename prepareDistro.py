import os
from lxml import etree as ET
import csv
import pandas as pd

def readPom(file):
    pom = ET.parse(file)
    items= pom.find('//{http://maven.apache.org/POM/4.0.0}properties')
    items=items[1:]
    hm={}
    for idx, item in enumerate(items):
        if item.tag is ET.Comment:
            print(str(item))
            if 'OWA' in item.text:
                break
            else:
                continue
    
        artifact= item.tag.replace('{http://maven.apache.org/POM/4.0.0}','').replace('Version','').strip().lower()
        hm[artifact]={}
        version=item.text.strip()
        if artifact == 'openmrs':
            group='org.openmrs'
            repoName='openmrs-core'
        else:
            group='org.openmrs.module'
            repoName='openmrs-module-'+artifact
        
        hm[artifact]['version']=version
        hm[artifact]['group']=group
        hm[artifact]['repo']=repoName

    assert len(hm)==43

    return hm 

    

if __name__=='__main__':
    hm = readPom('pom.xml')
    print(hm)