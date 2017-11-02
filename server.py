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
PIDS = []  # stores pids of all preforked children
BYTES_READ = 4096
BLOCK_ATTEMPTS = 3
TMP_BLOCK_TIME = 60 #sec
ONLINE_TIME = 60 * 60 #1 hour
USER_FILES = './server_resources/user_data/'

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

    obj = {
        'signup_timestamp': str(datetime.datetime.now()),
        'to_be_delivered': []
    }
    filename = USER_FILES + username + '.json'
    with open(filename, 'w+') as fp:
        json.dump(obj, fp)


def signup_server(sock, data):
    username = data['username']
    password = data['password']
    operation = data['operation']
    print("TEST")
    if ip_port_already_used(sock) :
        dict_to_send = {
            'status': 0,
            'message': 'already logged in',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    elif user_already_exists(username):
        dict_to_send = {
            'status': 0,
            'message': 'username already exists',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    else:
        add_user(username, password)
        print("ADD USER")
        dict_to_send = {
            'status': 1,
            'message': 'user successfully registered',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')

def is_user_blocked_tmp(sock, username):
    if username in user_info and 'block' in user_info[username] :
        for i, j in enumerate(user_info[username]['block']) :
            if user_info[username]['block'][i]['ip'] == sock.getpeername()[0] :
                if 'blocked' in user_info[username]['block'][i] :
                    if user_info[username]['block'][i]['blocked'] :
                        time_elapsed = datetime.datetime.now() - user_info[username]['block'][i]['block_time']
                        time_elapsed = time_elapsed.seconds
                        if time_elapsed <= TMP_BLOCK_TIME : #revisit this
                            return True
                        else :
                            user_info[username]['block'][i]['blocked'] = False
    return False

def is_user_already_logged(username):
    if username in user_info and 'online' in user_info[username] :
        if user_info[username]['online']:
            return True
    return False

def is_user_auth(username, password):
    with open('./server_resources/user_pass.csv') as csvfile:
        fieldnames = ['username', 'password']
        reader = csv.DictReader(csvfile, fieldnames=fieldnames)
        auth = False
        for row in reader:
            if row['username'] == username and row['password'] == password :
                auth = True
                break
    return auth

def username_exists(username):
    with open('./server_resources/user_pass.csv') as csvfile:
        fieldnames = ['username', 'password']
        reader = csv.DictReader(csvfile, fieldnames=fieldnames)
        for row in reader:
            if row['username'] == username :
                return True
    return False

def ip_port_already_used(sock):
    for i in user_info :
        if 'id' in user_info[i] :
            if user_info[i]['id'][0] == sock.getpeername()[0] and user_info[i]['id'][1] == sock.getpeername()[1] :
                return True
    return False

def login_server(sock, data):
    username = data['username']
    password = data['password']
    operation = data['operation']
    if username_exists(username) == False :
        dict_to_send = {
            'status': 0,
            'message': 'username does not exist',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    elif ip_port_already_used(sock) :
        dict_to_send = {
            'status': 0,
            'message': 'multiple logins not allowed from same IP and port',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    elif is_user_blocked_tmp(sock, username) :
        dict_to_send = {
            'status': 0,
            'message': 'user blocked',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    elif is_user_already_logged(username) :
        dict_to_send = {
            'status': 0,
            'message': 'user already logged in',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    else :
        auth = is_user_auth(username, password)
        if auth :
            obj_to_insert = {
                'online' : True,
                'login_time' : datetime.datetime.now(),
                'id' : sock.getpeername(),
                'socket' : sock
            }
            user_info[username] = obj_to_insert
            dict_to_send = {
                'status': 1,
                'message': 'user logged in successfully',
                'operation': operation
            }
            dict_to_send = json.dumps(dict_to_send)
            sock.sendall(dict_to_send+'|')
            send_stored_msg(sock, data)
        else:
            if username in user_info :
                if 'block' in user_info[username] :
                    is_present = False
                    for i, j in enumerate(user_info[username]['block']) :
                        if user_info[username]['block'][i]['ip'] == sock.getpeername()[0] :
                            user_info[username]['block'][i]['invalid_attempt_count'] += 1
                            if user_info[username]['block'][i]['invalid_attempt_count'] == BLOCK_ATTEMPTS :
                                user_info[username]['block'][i]['blocked'] = True
                                user_info[username]['block'][i]['block_time'] = datetime.datetime.now()
                                user_info[username]['block'][i]['invalid_attempt_count'] = 0
                                dict_to_send = {
                                    'status': 0,
                                    'message': 'login unsuccessful! user has been blocked for ' + str(TMP_BLOCK_TIME) + ' seconds',
                                    'operation': operation
                                }
                                dict_to_send = json.dumps(dict_to_send)
                                sock.sendall(dict_to_send+'|')
                            else :
                                dict_to_send = {
                                    'status': 0,
                                    'message': 'login unsuccessful',
                                    'operation': operation
                                }
                                dict_to_send = json.dumps(dict_to_send)
                                sock.sendall(dict_to_send+'|')
                            is_present = True
                            break
                    if is_present == False :
                        obj_to_insert = {
                            'ip' : sock.getpeername()[0],
                            'invalid_attempt_count' : 1
                        }
                        user_info[username]['block'].append(obj_to_insert)
                        dict_to_send = {
                            'status': 0,
                            'message': 'login unsuccessful',
                            'operation': operation
                        }
                        dict_to_send = json.dumps(dict_to_send)
                        sock.sendall(dict_to_send+'|')

                else :
                    user_info[username]['block'] = [{
                        'ip' : sock.getpeername()[0],
                        'invalid_attempt_count' : 1
                    }]
                    dict_to_send = {
                        'status': 0,
                        'message': 'login unsuccessful',
                        'operation': operation
                    }
                    dict_to_send = json.dumps(dict_to_send)
                    sock.sendall(dict_to_send+'|')
            else :
                obj_to_insert = {
                    'block' : [{
                        'ip' : sock.getpeername()[0],
                        'invalid_attempt_count' : 1
                    }]
                }
                user_info[username] = obj_to_insert
                dict_to_send = {
                    'status': 0,
                    'message': 'login unsuccessful',
                    'operation': operation
                }
                dict_to_send = json.dumps(dict_to_send)
                sock.sendall(dict_to_send+'|')

def logout_server(sock, operation=-1) :
    for i in user_info :
        if 'id' in user_info[i] :
            if user_info[i]['id'][0] == sock.getpeername()[0] and user_info[i]['id'][1] == sock.getpeername()[1] :
                user_info.pop(i, None)
                dict_to_send = {
                    'status': 1,
                    'message': 'user logged out successfully',
                    'operation': operation
                }
                dict_to_send = json.dumps(dict_to_send)
                sock.sendall(dict_to_send+'|')
                return
    dict_to_send = {
        'status': 0,
        'message': 'user was not logged in',
        'operation': operation
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send+'|')
    sock.close()

def is_user_logged_in(sock):
    for i in user_info :
        if 'id' in user_info[i] :
            if user_info[i]['id'][0] == sock.getpeername()[0] and user_info[i]['id'][1] == sock.getpeername()[1] :
                return True
    return False

def get_all_users_online():
    users_online = []
    for i in user_info :
        if 'online' in user_info[i] :
            if user_info[i]['online'] :
                users_online.append(i)
    return users_online

def get_last_hour_login():
    users_online = []
    for i in user_info :
        if 'online' in user_info[i] :
            if user_info[i]['online'] :
                time_elapsed = datetime.datetime.now() - user_info[i]['login_time']
                time_elapsed = time_elapsed.seconds
                if time_elapsed <= ONLINE_TIME :
                    users_online.append(i)
    return users_online

def users_online_server(sock, operation):
    if is_user_logged_in(sock) :
        users_online = get_all_users_online() #array
        dict_to_send = {
            'status': 1,
            'message': str(users_online),
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
        sock.sendall(dict_to_send+'|')
    else :
        dict_to_send = {
            'status': 0,
            'message': 'you are not logged in',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
        sock.sendall(dict_to_send+'|')

def last_hour_login_users_server(sock, operation):
    if is_user_logged_in(sock) :
        users_online = get_last_hour_login() #array
        dict_to_send = {
            'status': 1,
            'message': str(users_online),
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    else :
        dict_to_send = {
            'status': 0,
            'message': 'you are not logged in',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')

def is_user_online(username):
    if username in user_info :
        if 'online' in user_info[username] :
            if user_info[username]['online'] :
                return True
    return False

def get_username(sock):
    username = None
    for i in user_info :
        if 'id' in user_info[i] :
            if user_info[i]['id'][0] == sock.getpeername()[0] and user_info[i]['id'][1] == sock.getpeername()[1] :
                username = i
                break
    return username

def get_sock(username):
    sock = None
    for i in user_info :
        if 'online' in user_info[username] :
            if user_info[username]['online'] :
                sock = user_info[username]['socket']
                break
    return sock

def private_msg_server(sock, data):
    operation = data['operation']
    if is_user_logged_in(sock) :
        print("Inside is_user_logged_in")
        rcpt_username = data['username']
        message = data['message']
        msg_timestamp = data['timestamp']
        sender_username = get_username(sock)
        if username_exists(rcpt_username) :
            print("Inside username_exists")
            if is_user_online(rcpt_username) :
                # TODO
                print("Inside is_user_online")
                rcpt_sock = get_sock(rcpt_username)
                print("RCPT_SOCK: ", rcpt_sock, rcpt_sock.getpeername())
                dict_to_send = {
                    'status': 2,
                    'message': message,
                    'operation': operation,
                    'sender': sender_username,
                    'timestamp': msg_timestamp
                }
                dict_to_send = json.dumps(dict_to_send)
                rcpt_sock.sendall(dict_to_send+'|')
            else :
                #TODO
                dict_to_send = {
                    'status': 2,
                    'message': message,
                    'operation': operation,
                    'sender': sender_username,
                    'timestamp': msg_timestamp
                }
                filename = USER_FILES + rcpt_username + '.json'
                data = None
                with open(filename, 'r') as fp:
                    data = json.load(fp)
                data['to_be_delivered'].append(dict_to_send)
                with open(filename, 'w+') as fp:
                    json.dump(data, fp)
        else :
            dict_to_send = {
                'status': 0,
                'message': 'no user by this username',
                'operation': operation
            }
            dict_to_send = json.dumps(dict_to_send)
            sock.sendall(dict_to_send+'|')
    else :
        dict_to_send = {
            'status': 0,
            'message': 'you are not logged in',
            'operation': operation
        }
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')

def send_stored_msg(sock, data):
    username = data['username']
    password = data['password']
    operation = data['operation']
    filename = USER_FILES + username + '.json'
    data = None
    with open(filename, 'r') as fp:
        data = json.load(fp)
    for i in range(0, len(data['to_be_delivered'])):
        dict_to_send = data['to_be_delivered'][i]
        dict_to_send = json.dumps(dict_to_send)
        sock.sendall(dict_to_send+'|')
    data['to_be_delivered'] = []
    with open(filename, 'w+') as fp:
        json.dump(data, fp)

def handle(sock):
    # read a line that tells us how many bytes to write back

    flag = True
    while flag:
        try:
            print("SOCK: ", sock.getpeername())
            data = sock.recv(BYTES_READ)
            try:
                data = json.loads(data)
                print("Operation: ", data['operation'])
                if data['operation'] == 1 :
                    signup_server(sock, data)
                elif data['operation'] == 2 :
                    login_server(sock, data)
                    print("user_info afer login: ", user_info)
                elif data['operation'] == 3 :
                    logout_server(sock, data['operation'])
                    print("user_info after logout: ", user_info)
                    flag = False
                elif data['operation'] == 4 :
                    users_online_server(sock, data['operation'])
                elif data['operation'] == 5 :
                    last_hour_login_users_server(sock, data['operation'])
                elif data['operation'] == 6 :
                    private_msg_server(sock, data)

            except:
                print("Client malfunctioned. Logging out client: ", sock.getpeername())
                logout_server(sock)
                print("user_info: ", user_info)
                flag = False
            
        except IOError as err:
            print("IOError: ", err)
            logout_server(sock)
            print("user_info: ", user_info)
            flag = False


def child_loop(index, listen_sock):
    while True:
        try:
            conn, client_address = listen_sock.accept()
        except IOError as e:
            code, msg = e.args
            if code == errno.EINTR:
                continue
            else:
                raise

        handle(conn)


def create_child(index, listen_sock):
    thread.start_new_thread(child_loop,(index, listen_sock))
    child_loop(index, listen_sock)

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
    # signal.signal(signal.SIGTERM, _cleanup)

    # parent never calls 'accept' - children do all the work
    # all parent does is sleeping :)
    # signal.pause()


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