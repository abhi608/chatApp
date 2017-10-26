import os
import csv
import json
import errno
import signal
import socket
import thread
import optparse
import datetime

BACKLOG = 5

# stores pids of all preforked children
PIDS = []
# tmp = 0

BYTES_READ = 3000

user_info = {}

def user_already_exists(username):
    with open('./server_resources/user_pass.csv') as csvfile:
        fieldnames = ['username', 'password']
        reader = csv.DictReader(csvfile, fieldnames=fieldnames)
        exists = False
        for row in reader:
            if row['username'] == username :
                exists = True
                break
    return exists

def add_user(username, password):
    with open('./server_resources/user_pass.csv', 'a') as csvfile:
        fieldnames = ['username', 'password']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'username': username, 'password': password})

def signup_server(sock, data):
    username = data['username']
    password = data['password']
    if user_already_exists(username):
        dict_to_send = {
            'status': 0,
            'message': 'username already exists'
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send)
    else:
        add_user(username, password)
        dict_to_send = {
            'status': 1,
            'message': 'user successfully registered'
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send)

def is_user_blocked_tmp(username):
    #TODO
    if username in user_info and  'blocked' in user_info[username]:
        if user_info[username]['blocked'] :
            time_elapsed = datetime.datetime.now() - user_info[username]['block_time'] #revisit this
            time_elapsed = time_elapsed.seconds
            if time_elapsed <= 60 : #revisit this
                return True
            else :
                user_info[username]['blocked'] = False
                # user_info[username]['invalid_attempt_count'] = 0
    return False

def is_user_already_logged(username):
    #TODO
    print("TEST: ", str(username), user_info)
    x = 0
    if str(username) in user_info:
        print("YES")
    if username in user_info and 'online' in user_info[username] :
        if user_info[username]['online']:
            x=1
            return True
    print(x)
    return False

def is_user_auth(username, password):
    #TODO
    with open('./server_resources/user_pass.csv') as csvfile:
        fieldnames = ['username', 'password']
        reader = csv.DictReader(csvfile, fieldnames=fieldnames)
        auth = False
        for row in reader:
            if row['username'] == username and row['password'] == password :
                auth = True
                break
    return auth

def login_server(sock, data):
    print("TEST1: ", user_info)
    username = data['username']
    password = data['password']
    if is_user_blocked_tmp(username) :
        dict_to_send = {
            'status': 0,
            'message': 'user blocked'
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send)
    elif is_user_already_logged(username) :
        dict_to_send = {
            'status': 0,
            'message': 'user already logged in'
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send)
    else :
        auth = is_user_auth(username, password)
        if auth :
            obj_to_insert = {
                'online' : True,
                'login_time' : datetime.datetime.now()
            }
            user_info[username] = obj_to_insert
            dict_to_send = {
                'status': 1,
                'message': 'user successfully logged in'
            }
            dict_to_send = json.dumps(dict_to_send)
            sock.sendall(dict_to_send)
        else:
            if username in user_info :
                if 'invalid_attempt_count' in user_info[username] : # handy when client presses Ctrl+C
                    #TODO
                    user_info[username]['invalid_attempt_count'] += 1
                    if user_info[username]['invalid_attempt_count'] == 3:
                        user_info[username]['blocked'] = True
                        user_info[username]['block_time'] = datetime.datetime.now()
                        user_info[username]['invalid_attempt_count'] = 0
                        dict_to_send = {
                            'status': 0,
                            'message': 'login unsuccessful! user has been blocked for 60 seconds'
                        }
                        dict_to_send = json.dumps(dict_to_send)
                        sock.sendall(dict_to_send)
                    else :
                        dict_to_send = {
                            'status': 0,
                            'message': 'login unsuccessful'
                        }
                        dict_to_send = json.dumps(dict_to_send)
                        sock.sendall(dict_to_send)
                else :
                    #TODO
                    user_info[username]['invalid_attempt_count'] = 1
                    dict_to_send = {
                        'status': 0,
                        'message': 'login unsuccessful'
                    }
                    dict_to_send = json.dumps(dict_to_send)
                    sock.sendall(dict_to_send)
            else :
                obj_to_insert = {
                    'invalid_attempt_count' : 1,
                }
                user_info[username] = obj_to_insert
                dict_to_send = {
                    'status': 0,
                    'message': 'login unsuccessful'
                }
                dict_to_send = json.dumps(dict_to_send)
                sock.sendall(dict_to_send)

    print("User_info: ", user_info)



def handle(sock):
    # read a line that tells us how many bytes to write back

    flag = True
    while flag:
        try:
            # data = sock.recv(BYTES_READ)
            # print("DATA: ", data)
            # sock.sendall(data)
            print("SOCK: ", sock.getpeername())
            data = sock.recv(BYTES_READ)
            data = json.loads(data)
            print("data: ", data)
            if data['operation'] == 1 :
                signup_server(sock, data)
            elif data['operation'] == 2 :
                login_server(sock, data)
                print("user_information: ", user_info)
            flag = False
        except IOError as e:
            print("TEST: ", e)
            flag = False
            sock.close()
        # sock.close()


def child_loop(index, listen_sock):
    """Main child loop."""
    while True:
        # block waiting for connection to handle
        try:
            conn, client_address = listen_sock.accept()
        except IOError as e:
            code, msg = e.args
            if code == errno.EINTR:
                continue
            else:
                raise

        handle(conn)

        # close handled socket connection and off to handle another request
        # conn.close()


def create_child(index, listen_sock):
    # pid = os.fork()
    # if pid > 0: # parent
    #     return pid

    # print 'Child started with PID: %s' % os.getpid()
    # child never returns
    thread.start_new_thread(child_loop,(index, listen_sock))
    child_loop(index, listen_sock)


def _cleanup(signum, frame):
    """SIGTERM signal handler"""
    # terminate all children
    for pid in PIDS:
        try:
            os.kill(pid, signal.SIGTERM)
        except:
            pass

    # wait for all children to finish
    while True:
        try:
            pid, status = os.wait()
        except OSError as e:
            if e.errno == errno.ECHILD:
                break
            else:
                raise

        if pid == 0:
            break

    os._exit(0)


def serve_forever(host, port, childnum):
    # create, bind, listen
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # re-use the port
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listen_sock.bind((host, port))
    listen_sock.listen(BACKLOG)

    print 'Listening on port %d ...' % port

    # prefork children
    global PIDS
    PIDS = [create_child(index, listen_sock) for index in range(childnum)]

    # setup SIGTERM handler - in case the parent is killed
    signal.signal(signal.SIGTERM, _cleanup)

    # parent never calls 'accept' - children do all the work
    # all parent does is sleeping :)
    signal.pause()


def main():
    parser = optparse.OptionParser()
    parser.add_option(
        '-i', '--host', dest='host', default='0.0.0.0',
        help='Hostname or IP address. Default is 0.0.0.0'
        )

    parser.add_option(
        '-p', '--port', dest='port', type='int', default=2000,
        help='Port. Default is 2000')

    parser.add_option(
        '-n', '--child-num', dest='childnum', type='int', default=1,
        help='Number of children to prefork. Default is 10')

    options, args = parser.parse_args()

    serve_forever(options.host, options.port, options.childnum)

if __name__ == '__main__':
    main()