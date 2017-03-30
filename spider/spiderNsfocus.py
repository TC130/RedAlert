#coding:utf-8
import urllib
import re
import sys
import smtplib
from email.mime.text import MIMEText
from DB.dbOperation import *
from distutils.version import LooseVersion

reload(sys)
sys.setdefaultencoding('utf8')

def singleVulAppend(title,lower,op,higher,url):
    singleVul = []
    singleVul.append(title)
    singleVul.append(lower)
    singleVul.append(op)
    singleVul.append(higher)
    singleVul.append(url)

    return singleVul

def singleAlert(title,ip,owner,url,cur_ver,vul_ver):
    single_alert = []
    single_alert.append(title)
    single_alert.append(ip)
    single_alert.append(owner)
    single_alert.append(url)
    single_alert.append(cur_ver)
    single_alert.append(vul_ver)
    return single_alert

def getHtml(url):
    page = urllib.urlopen(url)
    html = page.read()
    return html

def getUrls(html):
    href = re.compile("<a href=\'(/vulndb.*?)\'>(.*)</a>")
    all = href.findall(html)
    for alert in all:

        #设置想要抓的关键字！！！！！！！！！！！！

        if (app in alert[1]) and (("远程代码执行" in alert[1]) or ("远程命令执行" in alert[1]) or ("远程拒绝服务" in alert[1])):
            #print app+"漏洞描述url为："
            #print alert[0]
            #把符合“代码执行”……等等条件的url摘出来去重存在set里
            urls.add("http://www.nsfocus.net" + alert[0].strip())

    #return urls

def grab(site,app):
    #设置一个全局的set来放置满足条件的漏洞url
    global urls
    #vul_list = []
    vul_list = []
    vul_list_all = []
    urls = set()
    sitePage = getHtml(site)
    getUrls(sitePage)
    #取当前有多少页，遍历所有页面的标题
    totalPages = re.findall("<span class=\"arial color\">\d+/(\d+)</span>",sitePage)
    try:
        num = totalPages[0]
        for currentPage in range(2,int(num),1):
            getUrls(getHtml("http://www.nsfocus.net/index.php?act=sec_bug&type_id=&os=&keyword="+app+"&page="+str(currentPage)))

        # #遍历urls的url
        for url in urls:
            vul_list = []
            #漏洞详情的页面
            html = getHtml(url)
            vul_title_list =  re.findall("<title>绿盟科技——巨人背后的专家\s+(.*?)</title>",html)
            vul_title = "".join(vul_title_list)
            vul_ver_re = re.compile("<b>受影响系统：</b><blockquote>([\s\S]*?)</blockquote><b>")
            vul_ver = vul_ver_re.findall(html)
            vul_version = ''.join(vul_ver)

            #字典中存储“漏洞名称”和“影响版本”
            vul_list.append(vul_title)
            vul_list.append(vul_version,)
            vul_list.append(url)
            vul_list_all.append(vul_list)
            #vul_list.append(str_convert)
    except Exception,e:
        print e

    print vul_list_all

    return vul_list_all

def analysis(vul_list_all):

    allVul = []

    for vul_info in vul_list_all:
        singleVul = []
        #print "vul:"
        title = vul_info[0]
        vul = vul_info[1]
        url = vul_info[2]
        #若里面有换行 则先把换行拆分一下！！！！！！！！！！！！！

        if "<br />" in vul :

            digest = vul.split("<br />")
            #因为有br 所以肯定会有一个list，先遍历list
            for dig_has_br in digest:
                #先清空列表
                singleVul = []
                #保险起见，先把br标签干掉
                dig = dig_has_br.strip("<br />")
                #print dig
                #todo 倒是mMicrosoft-IIS/8.5会有问题
                # 小于等于的情况：
                if "&lt;=" in dig:
                    left_right = re.findall("(\d+.*)\s?&lt;=\s?(\d+.*)", dig)
                    if left_right:
                        left_right = left_right[0]
                        lower = left_right[0]
                        higher = left_right[1]
                        print "多行数据 && <= &&左右两边都有版本"
                        #把名称、低版本、高版本都放到single里
                        allVul.append(singleVulAppend(title,lower,"LE",higher,url))

                        print lower, higher
                    else:
                        ver = re.findall("&lt;=\s?(\d+.*)", dig)
                        if ver:
                            print "多行数据 && <= &&只有右边有版本"
                            lower = "0"
                            higher = ver[0]

                            allVul.append(singleVulAppend(title, lower, "LE", higher, url))
                            print higher
                        else:
                            print "这个版本号太特殊了，有问题！！！！！！"+dig

                #特殊小于等于号的情况
                elif "〈=" in dig:
                    left_right = re.findall("(\d+.*)\s?〈=\s?(\d+.*)", dig)
                    if left_right:
                        left_right = left_right[0]
                        lower = left_right[0]
                        higher = left_right[1]
                        print "多行数据 && <= &&左右两边都有版本"

                        allVul.append(singleVulAppend(title,lower,"LE",higher,url))
                        print lower, higher
                    else:
                        ver = re.findall("〈=\s?(\d+.*)", dig)
                        if ver:
                            print "多行数据 && <= &&只有右边有版本"
                            lower = "0"
                            higher = ver[0]

                            allVul.append(singleVulAppend(title, lower, "LE", higher, url))

                            print higher
                        else:
                            print "这个版本号太特殊了，有问题！！！！！！"+dig

                # 小于的情况：
                elif "&lt;" in dig:
                    left_right = re.findall("(\d+.*)\s?&lt;\s?(\d+.*)", dig)
                    if left_right:
                        left_right = left_right[0]
                        lower = left_right[0]
                        higher = left_right[1]
                        print "多行数据 && < &&左右两边都有版本"

                        allVul.append(singleVulAppend(title,lower,"L",higher,url))

                        print lower, higher
                    else:
                        ver = re.findall("&lt;\s?(\d+.*)", dig)
                        if ver:
                            print "多行数据 && < &&只有右边有版本"

                            lower = "0"
                            higher = ver[0]

                            allVul.append(singleVulAppend(title, lower, "L", higher, url))

                            print higher
                        else:
                            print "这个版本号太特殊了，有问题！！！！！！"+dig

                # 特殊小于号的情况
                elif "〈" in dig:
                    left_right = re.findall("(\d+.*)\s?〈\s?(\d+.*)", dig)
                    if left_right:
                        left_right = left_right[0]
                        lower = left_right[0]
                        higher = left_right[1]
                        print "多行数据 && < &&左右两边都有版本"

                        allVul.append(singleVulAppend(title, lower, "L", higher, url))

                        print lower, higher
                    else:
                        ver = re.findall("〈\s?(\d+.*)", dig)
                        if ver:
                            print "多行数据 && < &&只有右边有版本"
                            lower = "0"
                            higher = ver[0]

                            allVul.append(singleVulAppend(title, lower, "L", higher, url))

                            print higher
                        else:
                            print "这个版本号太特殊了，有问题！！！！！！"+dig

                # 横杠的情况：
                elif "-" in dig:
                    left_right = re.findall("(\d+.*)\s?-\s?(\d+.*)", dig)
                    # print left_right
                    if left_right:
                        # 获取元组
                        left_right = left_right[0]
                        lower = left_right[0]
                        higher = left_right[1]
                        print "多行数据 && - && 左右两边都有版本"

                        allVul.append(singleVulAppend(title, lower, "L", higher, url))

                        print lower, higher
                    else:
                        ver = re.findall("-\s?(\d+.*)", dig)
                        if ver:
                            print "多行数据 && - && 只有右边有版本"
                            lower = "0"
                            higher = ver[0]

                            allVul.append(singleVulAppend(title, lower, "L", higher, url))

                            print higher
                        else:
                            print "这个版本号太特殊了，有问题！！！！！！"+dig


                # 没有符号，直接是特定版本的情况：
                else:
                    ver = re.findall("(\d+.*)", dig)
                    if ver:
                        print "多行数据 && 没有符号，直接是特定版本的情况："
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "E", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！"+dig



        #如果结果只有单行！！！！！！！！！！！！
        else:
            dig = vul
            #  小于等于的情况：
            if "&lt;=" in dig:
                left_right = re.findall("(\d+.*)\s?&lt;=\s?(\d+.*)",dig)
                if left_right:
                    left_right = left_right[0]
                    lower = left_right[0]
                    higher = left_right[1]
                    print "单行 && <= &&左右两边都有版本"

                    allVul.append(singleVulAppend(title, lower, "LE", higher, url))

                    print lower, higher
                else:
                    ver = re.findall("&lt;=\s?(\d+.*)", dig)
                    if ver:
                        print "单行 && <= &&只有右边有版本"
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "LE", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！" + dig

            #  特殊小于等于号的情况
            elif "〈=" in dig:
                left_right = re.findall("(\d+.*)\s?〈=\s?(\d+.*)", dig)
                if left_right:
                    left_right = left_right[0]
                    lower = left_right[0]
                    higher = left_right[1]
                    print "单行 && <= &&左右两边都有版本"

                    allVul.append(singleVulAppend(title, lower, "LE", higher, url))

                    print lower, higher
                else:
                    ver = re.findall("〈=\s?(\d+.*)", dig)
                    if ver:
                        print "单行 && <= &&只有右边有版本"
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "LE", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！" + dig


            #  小于的情况，还要判断左右两边的数据：
            elif "&lt;" in dig:
                left_right = re.findall("(\d+.*)\s?&lt;\s?(\d+.*)", dig)
                if left_right:
                    left_right = left_right[0]
                    lower = left_right[0]
                    higher = left_right[1]
                    print "单行 && < &&左右两边都有版本"

                    allVul.append(singleVulAppend(title, lower, "L", higher, url))

                    print lower, higher
                else:
                    ver = re.findall("&lt;\s?(\d+.*)", dig)
                    if ver:
                        print "单行 && < &&只有右边有版本"
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "L", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！" + dig

            #  特殊小于号的情况
            elif "〈" in dig:
                left_right = re.findall("(\d+.*)\s?〈\s?(\d+.*)", dig)
                if left_right:
                    left_right = left_right[0]
                    lower = left_right[0]
                    higher = left_right[1]
                    print "单行 && < &&左右两边都有版本"

                    allVul.append(singleVulAppend(title, lower, "L", higher, url))

                    print lower, higher
                else:
                    ver = re.findall("〈\s?(\d+.*)", dig)
                    if ver:
                        print "单行 && < &&只有右边有版本"
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "L", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！" + dig



            #  横杠的情况：
            elif "-" in dig:
                left_right = re.findall("(\d+.*)\s?-\s?(\d+.*)", dig)
                if left_right:
                    # 获取元组
                    left_right = left_right[0]
                    lower = left_right[0]
                    higher = left_right[1]
                    print "单行 && - &&左右两边都有版本"

                    allVul.append(singleVulAppend(title, lower, "L", higher, url))

                    print lower, higher
                else:
                    ver = re.findall("-\s?(\d+.*)", dig)
                    if ver:
                        print "单行 && - &&只有右边有版本"
                        lower = "0"
                        higher = ver[0]

                        allVul.append(singleVulAppend(title, lower, "E", higher, url))

                        print higher
                    else:
                        print "这个版本号太特殊了，有问题！！！！！！" + dig

            #  没有符号，直接是特定版本的情况：
            else:
                ver = re.findall("(\d+.*)", dig)
                if ver:
                    print "多行数据 && 没有符号，直接是特定版本的情况："
                    lower = "0"
                    higher = ver[0]
                    # singleVul.append(title)
                    # singleVul.append(lower)
                    # singleVul.append("E")
                    # singleVul.append(higher)
                    # singleVul.append(url)
                    # allVul.append(singleVul)
                    allVul.append(singleVulAppend(title, lower, "E", higher, url))

                    print higher
                else:
                    print "这个版本号太特殊了，有问题！！！！！！" + dig
        #把所有漏洞的个体（名称、低版本、高版本）都汇总到allVul这个大list里
    # allVul.append(singleVul)

    return allVul


def compare(allVul,curVerList):
    #print allVul
    alert_list = []
    for cur in curVerList:
        (ip, cur_ver, owner) = cur
        cur_ver = LooseVersion(cur_ver)
        for single in allVul:
            (title,lower,operator,higher,url) = single
            lower = LooseVersion(lower)
            higher = LooseVersion(higher)
            # 既要和高比 又要和低比！
            cmp_with_low = cmp(cur_ver,lower)
            cmp_with_high = cmp(cur_ver,higher)
            #如果原文中是小于，并且当前版本属于受影响范围内
            #todo 加一个受影响版本
            if (operator == "L") and ((cmp_with_low == 1) and (cmp_with_high == -1)):
                alert_list.append(singleAlert(title,ip,owner,url,str(cur_ver),"<"+str(higher)+"版本"))
            elif (operator == "LE") and ((cmp_with_low == 1) and ((cmp_with_high == -1) or (cmp_with_high == 0))):
                alert_list.append(singleAlert(title,ip,owner,url,str(cur_ver),"<="+str(higher)+"版本"))
            elif (operator == "E") and (cmp_with_high == 0):
                alert_list.append(singleAlert(title,ip,owner,url,str(cur_ver),"等于"+str(higher)+"版本"))
            else:
                print "啥也没查出来。。。。。。"

    return alert_list






def send_plain_mail(to_list,title,content):
    host = "mail.xxx.com"
    username = "security"
    password = "xxxxxxxxx"
    postfix = "xxx.com"
    me="<"+username+"@"+postfix+">"
    msg = MIMEText(content,_subtype='plain',_charset='utf-8')
    msg['Subject'] = title
    msg['From'] = me
    msg['To'] = to_list
    try:
        server = smtplib.SMTP()
        server.connect(host)
        server.login(username,password)
        server.sendmail(me, to_list, msg.as_string())
        server.close()
        return True
    except Exception, e:
        print str(e)
        return False



def sendMail(title, ip, owner, url, cur_ver, vul_ver):
    email_title = title
    to_list = owner

    email_content = "您好：\n    您所负责的服务器"+ip+"存在下列问题："+title+"\n    受影响版本为："+vul_ver+"\n    当前版本为："+cur_ver+"；\n    漏洞详情请见如下URL：\n    "+url+"\n    请及时修复漏洞，谢谢。"

    if send_plain_mail(to_list,email_title,email_content):
        print "send success !"
    else:
        print "send failed !"

def checkVul(alert_list):
    for alert in alert_list:
        (title, ip, owner, url, cur_ver, vul_ver) = alert
        res = vulSelect(ip,title)
        if res:
            #todo 如果里面有数据，说明之前发过，则先不发邮件了
            continue
        else:
            vulInsert(ip,title,"1")
            sendMail(title, ip, owner, url, cur_ver, vul_ver)




def search():
    appSet = set()
    allApps = appSelectName()
    for i in allApps:
        a = i[0]
        appSet.add(a)
    for i in appSet:
        global app
        app = i
        #todo 设置黑名单 把Apache排除出去
        if app!="Apache":
            site = "http://www.nsfocus.net/index.php?os=&type_id=&keyword=" + app + "&act=sec_bug&submit=+"
            allVul = analysis(grab(site, app))
            sendlist = compare(allVul, appSelectVer(app))
            # 如果漏洞列表不为空
            if sendlist:
                # todo 同时写进数据库vul表里，先查询有没有，没有就添加并置为1，如果有则检查是否为1，如果是1 则不发送邮件
                checkVul(sendlist)
            else:
                print "列表为空，没有漏洞"

search()
