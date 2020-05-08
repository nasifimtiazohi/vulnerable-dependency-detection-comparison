import pymysql

connection = pymysql.connect(host='localhost',
                             user='root',
                             db='openmrsvd',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor,
                             autocommit=True)
def execute(query):
    with connection.cursor() as cursor:
        cursor.execute(query)
        results = cursor.fetchall()
    return results