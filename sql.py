import pymysql
import pandas as pd
import csv
import os
database='openmrs'
import sqlalchemy as db
engine = db.create_engine('mysql+pymysql://root:@localhost:3306/{}'.format(database))

connection = pymysql.connect(host='localhost',
                             user='root',
                             db=database,
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
    q='SHOW COLUMNS FROM {}.{};'.format(database,table)
    r=execute(q)
    cols=[]
    for row in r:
        cols.append(row['Field'])
    df=df[cols]
    df.to_sql(table, engine, if_exists='append',index=False,schema=database)
    
if __name__=='__main__':
    q='select * from repository'
    execute(q)