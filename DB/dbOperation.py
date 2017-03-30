#coding:utf-8
import MySQLdb
from DBUtils.PooledDB import PooledDB

def appInsert(app,ip,cur_version,owner,business,safe_verion,announced):

    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306, use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'app': app,
        'ip': ip,
        'cur_version': cur_version,
        'owner': owner,
        'business': business,
        'safe_verion': safe_verion,
        'announced': announced
    }

    cur.execute("""
                INSERT INTO apps (`app`, `ip`, `cur_version`, `owner`, `business`, `safe_verion`, `announced`)
                VALUES
                    (%(app)s, %(ip)s, %(cur_version)s, %(owner)s, %(business)s, %(safe_verion)s, %(announced)s)
            """, data)

    conn.commit()
    cur.close()
    conn.close()

def appUpdate(app,ip,cur_version,owner,business,safe_verion,announced):


    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306, use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'app': app,
        'ip': ip,
        'cur_version': cur_version,
        'owner': owner,
        'business': business,
        'safe_verion': safe_verion,
        'announced': announced,
        'id': id,

    }

    cur.execute("""
                UPDATE `apps` SET `owner`=(%(app)s) WHERE (`id`=(%(id)s))
            """, data)

    conn.commit()
    cur.close()
    conn.close()




def appSelectAll(app,ip):

    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306 , use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'app': app,
        'ip': ip

    }

    cur.execute("""
                SELECT * FROM `apps` WHERE (`app`=%(app)s AND `ip`=%(ip)s)
            """, data)
    result = cur.fetchone();
    conn.commit()
    cur.close()
    conn.close()

    return result



def appSelectVer(app):
    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306 , use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'app': app
    }

    num = cur.execute("""
                SELECT ip,cur_version,owner FROM `apps` WHERE (`app`=%(app)s)
            """, data)
    result = cur.fetchmany(num)

    conn.commit()
    cur.close()
    conn.close()

    return result

def appSelectName():
    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306 , use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()


    num = cur.execute("""
                SELECT app FROM `apps`
            """)
    result = cur.fetchmany(num)

    conn.commit()
    cur.close()
    conn.close()

    return result
#print appSelectVer("OpenSSH")





def assetInsert(ip,owner,business):

    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306, use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'ip': ip,
        'owner': owner,
        'business': business
    }

    cur.execute("""
                INSERT INTO asset (`ip`,`owner`, `business`)
                VALUES
                    (%(ip)s, %(owner)s, %(business)s)
            """, data)

    conn.commit()
    cur.close()
    conn.close()


def assetOwnerSelect(ip):

    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306, use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'ip': ip

    }

    cur.execute("""
                    SELECT owner FROM `asset` WHERE (`ip`=%(ip)s)
                """, data)
    result = cur.fetchone();

    conn.commit()
    cur.close()
    conn.close()

    return result


def assetBusinessSelect(ip):

    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306, use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'ip': ip

    }

    cur.execute("""
                    SELECT business FROM `asset` WHERE (`ip`=%(ip)s)
                """, data)
    result = cur.fetchone();

    conn.commit()
    cur.close()
    conn.close()

    return result

def vulSelect(ip,title):
        pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306,
                        use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

        conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
        cur = conn.cursor()

        data = {
            'ip': ip,
            'title': title

        }

        num = cur.execute("""
                        SELECT * FROM `vul` WHERE (`ip`=%(ip)s AND `title`=%(title)s)
                    """, data)
        result = cur.fetchmany(num)

        conn.commit()
        cur.close()
        conn.close()

        return result


def vulInsert(ip,title,time):
    pool = PooledDB(MySQLdb, 6, host='localhost', user='root', passwd='qwerasdf', db='apps', port=3306,
                    use_unicode=True, charset="utf8")  # 5为连接池里的最少连接数

    conn = pool.connection()  # 以后每次需要数据库连接就是用connection（）函数获取连接就好了
    cur = conn.cursor()

    data = {
        'ip': ip,
        'title': title,
        'time': time
    }

    cur.execute("""
                  INSERT INTO vul (`ip`,`title`, `time`)
                  VALUES
                      (%(ip)s, %(title)s, %(time)s)
              """, data)

    conn.commit()
    cur.close()
    conn.close()


#vulInsert("10.1.1.2", "OpenSSH未处理","1")
#print appSelect("OpenSSH","10.2.209.1")