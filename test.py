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


ECHO_CODE = '''\
exports.handle = function (socket) {
  socket.write(socket.read());
};
'''


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
SELECT ak.create_schema(':echo');
SELECT ak.create_schema(':pg_default:echo:debug');
''')
        conn.commit()
        conn.close()

        if os.path.exists(TMP_PATH):
            shutil.rmtree(TMP_PATH)
        os.makedirs(DATA_PATH + '/apps/echo/code')
        os.makedirs(DATA_PATH + '/apps/echo/media')
        write(DATA_PATH + '/apps/echo/admin', 'pg_default')
        write(DATA_PATH + '/apps/echo/code/main.js', ECHO_CODE)
        os.makedirs(DATA_PATH + '/devs/pg_default/echo/envs/debug')
        os.makedirs(DATA_PATH + '/devs/pg_default/echo/code')
        write(DATA_PATH + '/devs/pg_default/echo/code/main.js', ECHO_CODE)
        os.mkdir(LOCKS_PATH)

        write(PATSAK_CONFIG_PATH, '''\
db=dbname=%s
lib=%s
''' % (DB_NAME, os.path.abspath(LIB_PATH)))
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
        self.assertEqual(
            request('debug.echo.pg_default.dev.akshell.com', 'hi'), 'hi')
        self.assertEqual(
            request('x.debug.echo.pg_default.dev.akshell.com', 'hi'), 'hi')
        self.assertEqual(request('x.echo.akshell.com', 'hello'), 'hello')
        self.assertEqual(request('x.echo.akshell.com', 'hello'), 'hello')
        self.assertEqual(control('STOP echo.akshell.com'), '')
        self.assertEqual(control('EVAL echo.akshell.com', '2+2'), 'S4')
        self.assertEqual(
            control('EVAL echo.akshell.com', 'throw 1'),
            'FUncaught 1\n    at 1:0')
        self.assert_(
            'Application bad' in request('bad.akshell.com'))
        self.assert_(
            'Environment bad' in request('bad.echo.pg_default.dev.akshell.com'))
        self.assert_(
            'Workspace bad' in request('debug.bad.pg_default.dev.akshell.com'))
        self.assert_(
            'Developer bad' in request('debug.echo.bad.dev.akshell.com'))
        self.assertRaises(socket.error, request, 'bad.dev.akshell.com')
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
