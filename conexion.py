import pymysql


def conectar(secret, database=None):
    return pymysql.connect(
        host=secret['host'],
        port=int(secret.get('port', 3306)),
        user=secret['username'],
        password=secret['password'],
        database=database,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
        autocommit=True,
        charset='utf8mb4',
    )
