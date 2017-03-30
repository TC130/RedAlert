#coding:utf-8

from collections import OrderedDict

from pyexcel_xls import get_data
from pyexcel_xls import save_data
from DB.dbOperation import *
import re
import os


def read_xls_file():
    xls_data = get_data("d:\\assets.xlsx")

    #从excel中读出漏洞信息这个sheet
    assetList = xls_data[u'虚拟机服务器']
    print assetList
    for i in range(0, len(assetList), 1):
        ip = assetList[i][0]
        owner = assetList[i][1]
        business = assetList[i][2]

        assetInsert(ip,owner,business)

read_xls_file()