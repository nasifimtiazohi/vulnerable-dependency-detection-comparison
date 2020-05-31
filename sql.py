import pymysql
import pandas as pd
import csv
import os

import sqlalchemy as db
engine = db.create_engine('mysql+pymysql://root:@localhost:3306/openmrsvd')

connection = pymysql.connect(host='localhost',
                             user='root',
                             db='openMRS',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor,
                             autocommit=True,
                             local_infile=True)
def execute(query):
    with connection.cursor() as cursor:
        cursor.execute(query)
        results = cursor.fetchall()
    return results

def pd_read_sql(query):
    return pd.read_sql(query,connection)

def load_df(table,df):
    #check if column names are in order
    cols=pd_read_sql('''select COLUMN_NAME
            from INFORMATION_SCHEMA.COLUMNS
            where TABLE_NAME='{}';'''.format(table))['COLUMN_NAME']
    df=df[cols]
    df.to_sql(table, engine, if_exists='append',index=False,schema='openmrsvd')
    
if __name__=='__main__':
    q='select * from repository'
    execute(q)