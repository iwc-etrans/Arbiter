# -*- coding: utf-8 -*-
# @Time    : 2020/9/25 13:35
# @Author  : Fcvane
# @Param   : 
# @File    : common.py

import logging.handlers
import datetime
import os, sys
import base64
from Crypto import Random
from Crypto.Cipher import AES


# 公共变量
class Variable():
    # 脚本路径
    ROOT_PATH = os.path.dirname(os.getcwd())
    # 配置文件路径
    CONF_PATH = os.path.abspath(ROOT_PATH + os.sep + 'conf')
    # 数据库配置路径
    DB_PATH = os.path.abspath(CONF_PATH + os.sep + 'dbParams')
    # JSON配置路径
    JSON_PATH = os.path.abspath(CONF_PATH + os.sep + 'json')
    # 日志文件路径
    LOG_PATH = os.path.abspath(ROOT_PATH + os.sep + 'log')
    # 临时文件目录
    TMP_PATH = os.path.abspath(ROOT_PATH + os.sep + 'tmp')
    # 组件目录
    PLG_PATH = os.path.abspath(ROOT_PATH + os.sep + 'plugin')
    # 结果文件目录
    RST_PATH = os.path.abspath(ROOT_PATH + os.sep + 'result')


# 日志工具
class Logger(logging.Logger):
    def __init__(self, name):
        super(Logger, self).__init__(self)
        self.name = name

        currDate = datetime.datetime.now().strftime('%Y-%m-%d')
        logFile = Variable().LOG_PATH + os.sep + '{name}_{currDate}.log'.format(name=name, currDate=currDate)

        fh = logging.FileHandler(logFile, mode='a')
        ch = logging.StreamHandler()
        # 调式
        ch.setLevel(logging.INFO)
        # ch.setLevel(logging.WARNING)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            # '[ %(asctime)s ] - [ %(filename)15s ] - [ line:%(lineno)5d ] - %(levelname)5s : %(message)s', )
            '[ %(asctime)s ] - [ %(filename)s ] - [ line:%(lineno)d ] - %(levelname)s : %(message)s', )
        # datefmt='%Y-%m-%d %H:%M:%S')
        # 获取logger名称
        logger = logging.getLogger()
        # 设置日志级别
        logger.setLevel(logging.INFO)

        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # 避免日志重复
        if not logger.handlers:
            self.addHandler(fh)
            # 控制台打印
            self.addHandler(ch)


name = os.path.basename(__file__).split('.')[0]
log = Logger(name)


# 加密&解密工具
class Crypter():
    @staticmethod
    def encrypt(originalPassword):
        bs = AES.block_size
        pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
        paddPassword = pad(originalPassword)
        iv = Random.OSRNG.new().read(bs)
        key = os.urandom(32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encryptPassword = base64.b64encode(iv + cipher.encrypt(paddPassword) + key)
        log.info('密码加密成功，结果：' + str(encryptPassword))
        return encryptPassword

    @staticmethod
    # 解密函数
    def decrypt(encryptPassword):
        base64Decoded = base64.b64decode(encryptPassword)
        bs = AES.block_size
        unpad = lambda s: s[0:-s[-1]]
        iv = base64Decoded[:bs]
        key = base64Decoded[-32:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        originalPassword = unpad(cipher.decrypt(base64Decoded[:-32]))[bs:]
        # log.info('密码解密成功，结果：' + str(originalPassword))
        # 解密后的bytes抓换
        return str(originalPassword, encoding="utf8")


import pymysql
import cx_Oracle
import psycopg2


# 数据库操作
class DbManager():
    # 构建
    def __init__(self, host, port, user, passwd, dbname, dbtype):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.dbname = dbname
        self.dbtype = dbtype.lower()
        self.conn = None
        self.cur = None

    # 连接
    # 支持oracle \ mysql \ postgresql
    def dbconnect(self):
        try:
            if self.dbtype == 'mysql':
                self.conn = pymysql.connect(host=self.host, port=int(self.port), user=self.user,
                                            passwd=self.passwd,
                                            db=self.dbname,
                                            charset='utf8')
            elif self.dbtype == 'oracle':
                self.conn = cx_Oracle.connect(self.user, self.passwd,
                                              '{ip}:{port}/{sid}'.format(ip=self.host, port=self.port, sid=self.dbname))
            elif self.dbtype == 'postgresql':
                self.conn = psycopg2.connect(host=self.host, port=self.port, user=self.user, password=self.passwd,
                                             database=self.dbname)
            else:
                log.error("数据库类型错误，请检查后重新处理")
                sys.exit()
            # log.info("数据库连接成功")
            self.cur = self.conn.cursor()
        except Exception as err:
            log.error("数据库连接失败，报错信息：" + str(err))
            return False
        return True

    # 释放
    def dbclose(self):
        if self.conn and self.cur:
            # log.info("释放数据库连接资源")
            self.cur.close()
            self.conn.close()
        return True

    # 查询一条数据
    # 注意不同数据库 参数方式不一致 如
    # oracle select * from tab where col=:col  params {'col':'**'}
    # mysql select * from tab where col=%s  params ('**',)
    def dbfetchone(self, sql, params=None):
        # 连接数据库
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            self.cur.execute(sql, params)
            result = self.cur.fetchone()
            return result
        except Exception as err:
            log.error("数据库单条数据查询失败 " + str(err))
            return False
            sys.exit()
        finally:
            self.dbclose()

    # 批量控制
    # 类似游标处理，数据处理完成前不关闭连接
    def dbbatch(self, sql, params=None):
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            self.cur.execute(sql, params)
            return self.cur
        except Exception as err:
            log.error("数据库批量数据查询失败 " + str(err))
            return False
            sys.exit()
        finally:
            self.dbclose()

    # 查询所有数据
    def dbfetchall(self, sql, params=None):
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            self.cur.execute(sql, params)
            results = self.cur.fetchall()
            return results
        except Exception as err:
            log.error("数据库所有数据查询失败 " + str(err))
            return False
            # sys.exit()
        finally:
            self.dbclose()

    # 查询所有数据_避免'cx_Oracle.LOB' object has no attribute 'translate'
    def lbfetchall(self, sql, params=None):
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            self.cur.execute(sql, params)
            results = self.cur.fetchall()
            return results
        except Exception as err:
            log.error("数据库所有数据查询失败 " + str(err))
            return False
            # sys.exit()

    # 执行SQL
    def dbexecute(self, sql, params=None):
        # 连接数据库
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            rowcount = self.cur.execute(sql, params)
            self.conn.commit()
            # log.info("执行SQL成功")
        except Exception as err:
            log.error("执行失败的SQL信息: " + sql + "_" + "参数信息: " + str(params))
            log.error("报错信息: " + str(err))
            return False
            sys.exit()
        finally:
            self.dbclose()
        return rowcount

    # 批量执行SQL
    def dbexecutemany(self, sql, params=None):
        # 连接数据库
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
        try:
            rowcount = self.cur.executemany(sql, params)
            self.conn.commit()
            # log.info("批量执行SQL成功")
            return rowcount
        except Exception as err:
            log.error("批量执行失败的SQL信息: " + sql + "_" + "参数信息: " + str(params))
            log.error("报错信息: " + str(err))
            return False
            sys.exit()
        finally:
            self.dbclose()

    # 执行 避免多次进行数据库的连接
    def sql_execute(self, sql, params=None):
        res = self.dbconnect()
        if not res:
            return False
            sys.exit()
            # try:
        self.cur.execute(sql)
        self.conn.commit()
        # except Exception as err:
        #     log.error("sql执行异常: " + str(err))


# print(Crypter.encrypt('abc123'))

# xml解析
try:
    import xml.etree.cElementTree as etree
except ImportError:
    import xml.etree.ElementTree as etree


class xmler():
    def __init__(self, auth):
        self.auth = auth

    def dbCFGInfo(self):
        taskName = Variable().DB_PATH + os.sep + 'dbconf.xml'
        # log.info('解析XML文件 {taskName}'.format(taskName=taskName))
        result = {}
        try:
            tree = etree.parse(taskName)
            # 获得子元素
            elemlist = tree.findall('auth[@id="%s"]' % self.auth)
            # 遍历task所有子元素
            for elem in elemlist:
                array = {}
                for child in elem.getchildren():
                    # print(child.tag, ":", child.text)
                    if child.tag == "passwd":
                        if child.text is not None:
                            array[child.tag] = Crypter().decrypt(child.text)
                        else:
                            array[child.tag] = ''
                    else:
                        array[child.tag] = child.text
                result[elem.attrib['id']] = array
                # log.info('XML文件解析成功')
        except Exception as e:
            log.error('XML文件解析失败')
            sys.exit()
        # print(result)
        return result


if __name__ == '__main__':
    print(Crypter.encrypt('RES_CMJS_DEMO'))
    # dbsrc='ORACLE_10.45.59.246'
    # print(xmler(dbsrc).dbCFGInfo())
