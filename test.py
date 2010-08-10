#!/usr/bin/env python

# (c) 2010 by Anton Korenyushkin

import sys
import os
import shutil
import subprocess
import unittest
import socket
import signal
import psycopg2
import time
import errno


ECILOP_CMD = 'ecilop'
if len(sys.argv) > 1:
    ECILOP_CMD = sys.argv[1]
    del sys.argv[1]


DB_NAME = 'test-ecilop'
TMP_PATH  = '/tmp/ecilop'
SOCKET_PATH = TMP_PATH + '/socket'
DATA_PATH = TMP_PATH + '/data'
LOCKS_PATH = TMP_PATH + '/locks'
LOG_PATH = TMP_PATH + '/log'
ECILOP_CONFIG_PATH = TMP_PATH + '/ecilop.conf'
PATSAK_CONFIG_PATH = TMP_PATH + '/patsak.conf'
CURR_PATH = os.path.dirname(__file__)
ECILOP_PATH = CURR_PATH + '/' + ECILOP_CMD
PATSAK_PATH = CURR_PATH + '/../patsak/exe/common/patsak'
LIB_PATH = CURR_PATH + '/../patsak/lib'
INIT_PATH = CURR_PATH + '/../patsak/init.sql'
SPACE_COUNT = 128


def write(path, data):
    with open(path, 'w') as f:
        f.write(data)


def read(path):
    with open(path) as f:
        return f.read()


def popen(cmd):
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)


def launch(args):
    return popen([ECILOP_PATH, '--config', ECILOP_CONFIG_PATH] + args)


def talk(data):
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(SOCKET_PATH)
    sock.send(data)
    sock.shutdown(socket.SHUT_WR)
    try:
        return sock.recv(8192)
    finally:
        sock.close()


def request(host, message=''):
    return talk('GET ' + host + ' ' * SPACE_COUNT + message)


def control(command, message=''):
    return talk(command + ' ' * (SPACE_COUNT - len(command)) + message)


class Test(unittest.TestCase):
    def setUp(self):
        popen(['dropdb', DB_NAME]).wait()
        popen(['createdb', DB_NAME]).wait()
        conn = psycopg2.connect('dbname=' + DB_NAME)
        conn.cursor().execute(read(INIT_PATH) + '''
SELECT ak.create_schema('ecilop:echo');
SELECT ak.create_schema('ecilop:echo:debug');
''')
        conn.commit()
        conn.close()

        if os.path.exists(TMP_PATH):
            shutil.rmtree(TMP_PATH)
        echo_path = DATA_PATH + '/devs/ecilop/apps/echo'
        os.makedirs(echo_path + '/code')
        os.makedirs(echo_path + '/git')
        os.makedirs(echo_path + '/envs')
        write(echo_path + '/envs/debug', '')
        write(echo_path + '/code/main.js', '''
env = 'release';

exports.handle = function (socket) {
  socket.write(socket.read());
};
''')
        git_cmd = [
            'git',
            '--work-tree', echo_path + '/code',
            '--git-dir', echo_path + '/git',
            ]
        popen(git_cmd + ['init']).wait()
        popen(git_cmd + ['add', 'main.js']).wait()
        popen(git_cmd + ['commit', '-m', 'Initial commit']).wait()
        write(echo_path + '/code/main.js', '''
env = 'debug';

exports.handle = function (socket) {
  socket.write(socket.read().toString().toUpperCase());
};
''')
        os.mkdir(DATA_PATH + '/domains')
        write(DATA_PATH + '/domains/echo.akshell.com', '\t ecilop:echo\r\n')
        write(DATA_PATH + '/domains/echo.com', 'ecilop:echo ')
        os.mkdir(LOCKS_PATH)

        write(PATSAK_CONFIG_PATH, '''\
db=dbname=%s
lib=%s
git=%s/devs/%%s/apps/%%s/git
''' % (DB_NAME, os.path.abspath(LIB_PATH), DATA_PATH))
        write(ECILOP_CONFIG_PATH, '''\
socket=%s:600
data=%s
locks=%s
log=%s
patsak=%s
patsak-config=%s
timeout=1
''' % (SOCKET_PATH, DATA_PATH, LOCKS_PATH, LOG_PATH,
       PATSAK_PATH, PATSAK_CONFIG_PATH))

    def tearDown(self):
        popen(['killall', ECILOP_CMD])
        shutil.rmtree(TMP_PATH)

    def test(self):
        self.assertEqual(popen([ECILOP_PATH]).wait(), 1)
        self.assertEqual(launch(['--bad']).wait(), 1)
        self.assertEqual(launch(['--help']).wait(), 0)
        self.assertEqual(launch(['--socket', 'bad/socket']).wait(), 1)
        self.assertEqual(launch(['--background', '--log', 'bad/log']).wait(), 1)

        process = launch(['--patsak', 'bad/patsak'])
        self.assertEqual(
            process.stdout.readline(), 'Running at /tmp/ecilop/socket\n')
        self.assertEqual(
            process.stdout.readline(), 'Quit with Control-C.\n')
        self.assertRaises(socket.error, request, 'echo.akshell.com', 'hello')
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(), 0)

        process = launch([])
        process.stdout.readline()
        self.assertEqual(request('echo.akshell.com', 'hello'), 'hello')
        self.assertEqual(request('echo.com', 'hello'), 'hello')
        self.assertEqual(
            request('debug.echo.ecilop.dev.akshell.com', 'hi'), 'HI')
        self.assertEqual(
            request('release.echo.ecilop.dev.akshell.com', 'hi'), 'hi')
        self.assertEqual(
            request('x.debug.echo.ecilop.dev.akshell.com', 'hi'), 'HI')
        self.assertEqual(request('x.echo.akshell.com', 'hello'), 'hello')
        self.assertEqual(request('x.echo.akshell.com', 'hello'), 'hello')
        self.assertEqual(control('STOP ecilop:echo'), '')
        self.assertEqual(request('echo.com', 'hello'), 'hello')
        self.assertEqual(control('EVAL ecilop:echo', 'env'), 'Srelease')
        self.assertEqual(control('EVAL ecilop:echo:debug', 'env'), 'Sdebug')
        self.assertEqual(
            control('EVAL ecilop:echo:bad', 'env'),
            'EEnvironment bad not found')
        self.assertEqual(
            control('EVAL ecilop:echo', 'throw 1'),
            'FUncaught 1\n    at 1:0')
        self.assert_(
            'Domain bad.akshell.com' in request('bad.akshell.com'))
        self.assert_(
            'Environment bad' in request('bad.echo.ecilop.dev.akshell.com'))
        self.assert_(
            'App bad' in request('debug.bad.ecilop.dev.akshell.com'))
        self.assert_(
            'Developer bad' in request('debug.echo.bad.dev.akshell.com'))
        time.sleep(1)
        self.assert_(
            'Developer bad' in request('debug.echo.bad.dev.akshell.com'))
        self.assertEqual(request('echo.akshell.com', 'wake up'), 'wake up')
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(), 0)

        self.assertEqual(launch(['--background']).wait(), 0)
        self.assertEqual(request('echo.akshell.com', 'hello'), 'hello')


if __name__ == '__main__':
    unittest.main()
