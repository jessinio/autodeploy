#!/usr/bin/env python
#coding: utf-8

import re
import optparse
import paramiko
import pdb
import pty
import os
import sys
import time
import select
import shlex

DEBUG=True
OUTPUT=True

OUTPUT_DEV = sys.stdout
DEBUG_DEV = sys.stderr

PROMPT = r"\[\w.*@.*\](\$|#)"
USER_PROMPT = r"\[\w.*@.*\]\$"
ROOT_PROMPT = r"\[\w.*@.*\]#"

def output(info):
    if OUTPUT:
        print >> OUTPUT_DEV, info,

def debug(info):
    if DEBUG:
        print >> DEBUG_DEV, info

def get_option():
    parser = optparse.OptionParser()
    parser.add_option("--host", dest="host", help="host ip address", metavar="127.0.0.1")
    parser.add_option("--login_user", dest="login_user", help="user who want to login", metavar="nobody")
    parser.add_option("--login_password", default='', dest="login_password", help="password for who want to login", metavar="password")
    parser.add_option("--root_password", default='', dest="root_password", help="password for root (use by su command), also can be a filepath", metavar="password")
    parser.add_option("--end_prompt", default='PROMPT', dest="end_prompt", help="end flag string when run remote script", metavar="PROMPT")
    parser.add_option("--default_password", default='', dest="default_password", help="default password for root (use by su command)", metavar="password")
    parser.add_option("--expression", dest="expression", help="run in remote host", metavar="python /tmp/do.py")
    #parser.add_option("--root_password_file", dest="root_password_file", help="password list for who want to login", metavar="/tmp/root_password.list")
    parser.add_option("--timeout", default = 5, type="int", dest="timeout", help="wait for pty string output time", metavar="5")
    parser.add_option("--data_path", dest="data_path", help="copy to remote host", metavar="/var/www")
    parser.add_option("--output", dest="output", help="remote pty output information (stdout default", metavar="/tmp/auto.output")
    parser.add_option("--debug", dest="debug", help="autodeploy tools self debug (stderr default)", metavar="/tmp/auto.debug")
    parser.add_option("--root_pty", action="store_true", dest="root_pty", help="get pty shell")

    option = parser.parse_args()[0]

    # 选项检查
    if None in [option.host, option.login_user, option.data_path, option.expression]:
        parser.print_help()
        sys.exit(1)

    if option.output:
        OUTPUT_DEV = open(option.output, "w")
    if option.debug:
        DEBUG_DEV = open(option.debug, "w")
    if option.end_prompt == "PROMPT":
        option.end_prompt = PROMPT
    return option
    
def pw_to_dict(password_file):
    "密码文件转换成dict对象 {'172.16.2.10':'password'}"
    pattern = re.compile(r'[ ,\t]+')
    d = {}
    for line in open(password_file):
        try:
            ip, pw = pattern.split(line.strip())
            d.setdefault(ip, pw)
        except:
            pass
    return d

def _expect_str_from_sock(sock, pattern, timeout):
    '期待特定字符串'
    # 统一成iterable对象
    if isinstance(pattern, basestring):
        pattern = [pattern]

    # 从sock里读到的全部数据
    for i in range(len(pattern)):
        pattern[i] = re.compile(pattern[i])

    retval = ''

    while True:
        if select.select([sock, ], [],  [], timeout)[0]:
            retval += sock.recv(1024)
            for i, p in enumerate(pattern):
                if p.search(retval):
                # 返回数据 , 成功标志, 顺序
                    return retval, True, i
        else:
            # 没有数据, 失败标志, 0
            return retval, False, 0


class RemoteShell(object):
    def __init__(self, host, login_user, login_password, root_password, default_password=[], timeout=5):
        self.host = host
        self.login_user = login_user
        self.login_password = login_password
        if os.path.exists(root_password): 
            self.root_password = pw_to_dict(root_password)
        else:
            self.root_password = {host:root_password}
        self.timeout = timeout
        self.sock = None
        self.root_shell_sock = False
        # 复制到 远程服务器的文件
        self.remote_data_path = None
        self.ssh_client = None

    def login(self):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(self.host, username=self.login_user, password=self.login_password)
        channel = self.ssh_client.invoke_shell()
        self.sock = channel

        # 登陆时的提示符
        retval, flag, index = self.expect_str_from_sock( PROMPT )
        output(retval)
        debug("login")

    def expect_str_from_sock(self, pattern, timeout=False):
        '期待特定字符串'
        if timeout is False:
            timeout = self.timeout
        return _expect_str_from_sock(self.sock, pattern, timeout)

    def copy_to_remote(self, data_path):
        '复制文件到远程服务器'
        basename = os.path.basename(data_path)
        self.remote_data_path = "/tmp/%s_%s" % (basename, str(time.time()))

        sftp_client = self.ssh_client.open_sftp()
        if os.path.isdir(data_path):
            sftp_client.mkdir(self.remote_data_path)
            os.chdir(data_path)
            for root, dirs, files in os.walk("."):
                for d in dirs:
                    d = os.path.join(root, d)
                    d = os.path.join(self.remote_data_path, d)
                    d = os.path.abspath(d)
                    debug('create %s' % d)
                    sftp_client.mkdir( d )
                for f in files:
                    f = os.path.join(root, f)
                    copies = os.path.join(self.remote_data_path, f)
                    copies = os.path.abspath(copies)
                    debug('copy %s' % copies)
                    sftp_client.put(f, copies)
        else:
            debug('copy %s' % basename)
            sftp_client.put(data_path, self.remote_data_path)


    def remove_remote_data(self):
        '删除已经上传到远程服务器上数据'


    def get_root_shell(self):
        'root用户登陆'
        if not self.login_user == 'root':
            # 测试sudo命令
            retval, flag, i = self.pty_send_line('#run by autodeploy tools')
            output(retval)
            if self.pty_send_line('sudo -i', ROOT_PROMPT)[1]:
                debug("[sudo] get root shell")
            else:
                debug("can't call sudo, trying [su] command")
                retval, flag, i = self.pty_send_line('su -', 'Password:')
                output(retval)
                if flag:
                    retval, flag, i = self.pty_send_line(self.root_password[self.host], ROOT_PROMPT)
                    output(retval)
                    if flag:
                        debug("[su -] get root shell")
                    else:
                        print >>sys.stderr, "Can't get root shell"
                        sys.exit(1)
            
        
    def pty_send_line(self, cmd, expect_str=PROMPT, timeout=False):
        '运行远端服务器脚本'
        self.sock.send(cmd + "\n")
        retval, flag, i = self.expect_str_from_sock(expect_str, timeout)
        if not flag:
            debug("time out: %s" % cmd)
        return retval, flag, i


if __name__ == "__main__":
    option = get_option()
    shell = RemoteShell(option.host, \
                        option.login_user, \
                        option.login_password, \
                        option.root_password, \
                        option.default_password, \
                        option.timeout)
    shell.login()
    shell.copy_to_remote(option.data_path)
    if option.root_pty:
        shell.get_root_shell()
    #if option.expression:
    #    output(shell.pty_send_line("sleep 10", PROMPT, 0)[0])
    output(shell.pty_send_line(option.expression, option.end_prompt, None)[0])