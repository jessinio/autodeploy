#!/usr/bin/env python
#coding: utf-8

import os
import sys
import string
try:
    import paramiko
except:
    print >>sys.stderr, "can't import paramiko library"
    try:
        if raw_input("""Do you want to install paramiko library now ? 
[ need root permission and easy_install ]""") in "yY":
            os.system("easy_install paramiko")
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)


import re
import termios
import optparse
import pty
import time
import select
import shlex
import pdb
import traceback

DEBUG=True
OUTPUT=True

OUTPUT_DEV = sys.stdout
DEBUG_DEV = sys.stderr

PROMPT = r"\w.*@.*(\$|#)"
USER_PROMPT = r"\w.*@.*\$"
ROOT_PROMPT = r"\w.*@.*#"


def output(info):
    if OUTPUT:
        OUTPUT_DEV.write(info)
        OUTPUT_DEV.flush()

def debug(info):
    if DEBUG:
        DEBUG_DEV.write("  debug: " + info + '\n')
        DEBUG_DEV.flush()

def get_option():
    parser = optparse.OptionParser()
    parser.add_option("--host", dest="host", help="host ip address", \
                        metavar="127.0.0.1")
    parser.add_option("--login_user", dest="login_user", \
                        help="user who want to login", metavar="nobody")
    parser.add_option("--login_password", default='nopassword', dest="login_password", \
                        help="password for who want to login", metavar="password")
    parser.add_option("--root_password", default='', dest="root_password", \
                        help="password for root (use by su command), also can be a filepath", \
                        metavar="password")
    parser.add_option("--ssh_key", dest="ssh_key", \
                        help="ssh private key", metavar="~/.ssh/other_key")
    parser.add_option("--end_prompt", default='PROMPT', dest="end_prompt", \
                        help="end flag string when run remote script", metavar="PROMPT")
    parser.add_option("--expression", dest="expression", help="run in remote host", \
                        metavar="python {remote_data}/do.py")
    parser.add_option("--timeout", default = 5, type="int", dest="timeout", \
                        help="wait for pty string output time", metavar="5")
    parser.add_option("--data_path", dest="data_path", help="copy to remote host", \
                        metavar="/var/www")
    parser.add_option("--output", dest="output", help="remote pty output information (stdout default", \
                        metavar="/tmp/auto.output")
    parser.add_option("--debug", dest="debug", help="autodeploy tools self debug (stderr default)", \
                        metavar="/tmp/auto.debug")
    parser.add_option("--root_pty", action="store_true", dest="root_pty", help="get pty shell")

    option = parser.parse_args()[0]

    # 选项检查
    if None in [option.host, option.login_user, option.data_path, option.expression]:
        parser.print_help()
        print """\n\tExample:\n\t\tpython remote_shell.py \
--host=10.20.188.53 \
--login_user=jessinio --data_path=/tmp/do.sh \
--expression="sh {remote_data}" --root_pty \
--root_password=password"""
        sys.exit(1)

    if option.output:
        OUTPUT_DEV = open(option.output, "w")
    if option.debug:
        DEBUG_DEV = open(option.debug, "w")
    if option.end_prompt == "PROMPT":
        option.end_prompt = PROMPT
    if os.path.exists(option.host):
        # host参数为文件名, 转成list对象
        option.host = [ l.strip() for i in open(option.host) ]
    else:
        option.host = [option.host]
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
        pattern[i] = re.compile(pattern[i], re.M)

    retval = ''

    while True:
        if select.select([sock, ], [],  [], timeout)[0]:
            tmp = sock.recv(1024)
            retval += tmp
            for i, p in enumerate(pattern):
                if p.search(retval):
                # 返回数据 , 顺序
                    return retval, i
        else:
            # 没有数据, 失败(<0)
            return retval, -1


class RemoteShell(object):
    def __init__(self, host, login_user, \
                       login_password, \
                       root_password, \
                       ssh_key=None, \
                       timeout=5):
        self.host = host
        self.login_user = login_user
        self.login_password = login_password
        if os.path.exists(root_password): 
            # 指定密码文件, 从密码文件中取得数据
            self.root_password = pw_to_dict(root_password)
        else:
            self.root_password = {host:root_password}
        self.ssh_key = ssh_key
        self.timeout = timeout
        self.sock = None
        self.root_shell_sock = False
        # 复制到 远程服务器的文件
        self.remote_data_path = None
        self.ssh_client = None
        self.timestamp = time.strftime("%Y-%m-%d_%M-%S")

    def login(self):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not self.ssh_key:
            self.ssh_client.connect(self.host, username=self.login_user, password=self.login_password)
        else:
            self.ssh_client.connect(self.host, \
                                    username=self.login_user, \
                                    password=self.login_password, \
                                    key_filename=self.ssh_key)

        channel = self.ssh_client.invoke_shell()
        self.sock = channel

        # 登陆时的提示符
        retval, index = self.expect_str_from_sock( PROMPT )
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
        self.remote_data_path = "/tmp/%s_%s" % (basename, self.timestamp)

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
            #retval, i = self.pty_send_line('#run by autodeploy tools')
            #pdb.set_trace()
            retval, i = self.pty_send_line('sudo -p "sudo password:" -i', [ROOT_PROMPT, "^sudo password:"])
            if i == 0 :
                debug("[sudo] get root shell")
                return True
            else:
                if i == 1:
                    # 给sudo输入密码
                    retval, i = self.pty_send_line(self.login_password, [ROOT_PROMPT, "sudo password:"])
                    if i == 0 :
                        debug("[sudo] get root shell")
                        return True
                # 所有未知情况: 调用su命令

                # 发送 ctrl-C 字符
                # copy from pexpect
                #if hasattr(termios, 'VINTR'):
                #    char = termios.tcgetattr(self.sock)[6][termios.VINTR]
                #else:
                #    # platform does not define VINTR so assume CTRL-C
                #    char = '\x03' #chr(3)
                #self.sock.send(char)
                #retval, flag, i = self.pty_send_line('\x03', USER_PROMPT)
                #output(retval)
                self.sock.sendall('\x03')
                output(self.sock.recv(1024))
                #retval, flag, i = self.pty_send_line('\x03', USER_PROMPT)
                debug("can't call sudo, trying [su] command")
                retval, i = self.pty_send_line('su -', 'Password:')
                if i>-1 :
                    # 输入密码
                    retval, i = self.pty_send_line(self.root_password[self.host], ROOT_PROMPT)
                    if i>-1:
                        debug("[su -] get root shell")
                        return True
                    else:
                        print >>sys.stderr, "Can't get root shell"
                        sys.exit(1)
                else:
                    print >>sys.stderr, "[su] command exception"
            
        
    def pty_send_line(self, cmd, expect_str=PROMPT, timeout=False):
        '运行远端服务器脚本'
        self.sock.sendall(cmd + "\n")
        retval, i = self.expect_str_from_sock(expect_str, timeout)
        output(retval)
        if i < 0:
            debug("time out: %s" % cmd)
        return retval, i


if __name__ == "__main__":
    option = get_option()
    for host in option.host:
        shell = RemoteShell(host, \
                            option.login_user, \
                            option.login_password, \
                            option.root_password, \
                            option.ssh_key, \
                            option.timeout)
        shell.login()
        shell.copy_to_remote(option.data_path)
        if option.root_pty:
            if not shell.get_root_shell():
                print "Can't get root shell"
                sys.exit(1)
        #if option.expression:
        #    output(shell.pty_send_line("sleep 10", PROMPT, 0)[0])

        if "{remote_data}" in option.expression:
            expression = option.expression.replace("{remote_data}", shell.remote_data_path)
        else:
            expression = option.expression
        shell.pty_send_line(expression, option.end_prompt, None)
        print 
