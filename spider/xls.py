#coding:utf-8

from collections import OrderedDict

from pyexcel_xls import get_data
from pyexcel_xls import save_data
from DB.dbOperation import *
import re
import os


def GetFileList(dir, fileList):
    newDir = dir
    if os.path.isfile(dir):
        fileList.append(dir.decode('gbk'))
    elif os.path.isdir(dir):
        for s in os.listdir(dir):
            # 如果需要忽略某些文件夹，使用以下代码
            # if s == "xxx":
            # continue
            newDir = os.path.join(dir, s)
            GetFileList(newDir, fileList)
    return fileList




def read_xls_file():
    filelist = GetFileList('D:\\nsfocus_scan', [])
    #filelist = GetFileList('D:\\xxx', [])
    ip_re = re.compile("\d+\.\d+\.\d+\.\d+")
    for e in filelist:
        #print e
        ip_list = ip_re.findall(e)
        ip = ip_list[0]
        xls_data = get_data(e)

        #获取owner
        owner_list = assetOwnerSelect(ip)
        if owner_list!=None:
            owner = owner_list[0]
        else:
            owner = "None"

        #获取business
        business_list = assetBusinessSelect(ip)
        if business_list!=None:
            business = business_list[0]
        else:
            business = "None"


        #从excel中读出漏洞信息这个sheet
        vulList = xls_data[u'漏洞信息']

        #设置一个去重的集合，存放当前IP的app和version
        currentIPApps = set()
        #从第二行开始读
        for i in range(1,len(vulList),1):
            #取excel表中第4列的漏洞描述和第14列的版本信息
            #print vulList[i]
            name = vulList[i][3]
            try:
                version = vulList[i][13]
                if "/" in version:
                    if ("[" in version) and ("]" in version):
                        version_tmp = re.findall("\[(\w+.*/\d+.*)]",version)
                        if version_tmp:
                            version_str = "".join(version_tmp)
                        #可能存在glass/1.0 python1.0情况存在，所以现在只有一个/的情况是正确的
                            if version_str.count("/")!=1:
                                continue
                            elif r"\r" in version_str:
                                continue
                            else:
                                version_str = "".join(version_tmp)
                                if ("HTTP" in version_str) or ("ncacn_http" in version_str) or ("dropbear" in version_str) :
                                    continue
                                else:
                                    #只是单独改一下字符串
                                    if "Microsoft-IIS" in version_str:
                                        version_str = version_str.replace("Microsoft-IIS","IIS")
                                    currentIPApps.add(version_str)
                   #把版本信息直接存到set中进行去重
                    #todo 如果没有中括号，要重新判断字符串是否乱
                    else:
                        #可能存在glass/1.0 python1.0情况存在，所以现在只有一个/的情况是正确的

                        if version.count("/")!=1:
                            continue
                        elif r"\r" in version:
                            continue
                        else:
                            version = re.findall("(\w+.*/\d+.*)",version)
                            if version:
                                version_str = "".join(version)
                                if ("HTTP" in version_str) or ("ncacn_http" in version_str) or ("dropbear" in version_str):
                                    continue
                                else:
                                    if "Microsoft-IIS" in version_str:
                                        version_str = version_str.replace("Microsoft-IIS","IIS")
                                    currentIPApps.add(version_str)
            except Exception,e:
                print e
                continue
            # if (u"远程代码执行" in name) | (u"远程命令执行" in name) | (u"远程拒绝服务" in name):
            #     version = vulList[i][13]
            #     #如果版本信息中包含了/，说明是正确的版本信息内容
            #     if "/" in version:
            #        #把版本信息直接存到set中进行去重
            #         currentIPApps.add(version)


        #print currentIPApps
        if currentIPApps.__len__()!=0:
            for version in currentIPApps:
                app = version.split('/')[0]
                ver = version.split('/')[1]
                print app
                print ver

                appInfo = appSelectAll(app,ip)
                #print appInfo

                if appInfo!=None:
                # if len(appInfo)!=0:
                    # 如果数据库中有当前信息了，更新表内容
                    appUpdate(app, ip, ver, owner, business, "unknown", "yes")
                    print "更新"
                else:
                    #如果表中没有原来的信息，则直接新加入
                    appInsert(app, ip, ver, owner, business, "unknown", "yes")
                    print "新增"
        else:
            print ip+ u"安全"




read_xls_file()