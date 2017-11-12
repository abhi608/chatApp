###############################################################################
#                                                                             #
#   ChatApp: Client Script                                                    #
#                                                                             #
###############################################################################

import os
import sys
import json
import errno
import base64
import socket
import select
import datetime
import optparse

BYTES_READ = 4096
key = '1234567890123456' # key to encode the client password

# Key to encode the password of Client
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc))

# Client helper function to print operations
def print_operation():
    print("0 | List of options")
    print("1 | Sign up")
    print("2 | Log in")
    print("3 | Log out")
    print("4 | Who all are online")
    print("5 | List of users logged in within last hour")
    print("6 | Send private message")
    print("7 | Send broadcast message")
    print("8 | Block a user")
    print("9 | Unblock a user")

# Client helper function for signup
def signup_client(sock, operation_selected):
    username=raw_input('Enter username: ')
    password = raw_input('Enter password: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
        'password': encode(key, password)
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function for login
def login_client(sock, operation_selected):
    username=raw_input('Enter username: ')
    password = raw_input('Enter password: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
        'password': encode(key, password)
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function for private messaging
def private_msg_client(sock, operation_selected):
    username = raw_input('Enter username of the user: ')
    message = raw_input('Enter your message: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
        'message': message,
        'timestamp': str(datetime.datetime.now()) 
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function for broadcast
def broadcast_client(sock, operation_selected):
    message = raw_input('Enter your message: ')
    dict_to_send = {
        'operation': operation_selected,
        'message': message,
        'timestamp': str(datetime.datetime.now()) 
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function to block user
def block_user_client(sock, operation_selected):
    username = raw_input('Enter username to be blocked: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function to unblock user
def unblock_user_client(sock, operation_selected):
    username = raw_input('Enter username to be unblocked: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function for logout
def logout_client(sock, operation_selected) :
    dict_to_send = {
        'operation': operation_selected,
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)
    
# Client helper function to check users online
def users_online_client(sock, operation_selected):
    dict_to_send = {
        'operation': operation_selected,
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Client helper function to check last hour logged in users
def last_hour_login_users_client(sock, operation_selected):
    dict_to_send = {
        'operation': operation_selected,
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)

# Local helper function to check if the input is an integer
def is_integer(operation):
    try: 
        int(operation)
        return True
    except ValueError:
        return False

def request(host, port, child_num, con_num):
    # spawn child_num children processes
    for cnum in range(child_num):

        pid = os.fork()
        if pid == 0: # child

            for i in range(con_num):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                input = [sock, sys.stdin]
                flag = True
                print_operation()
                data = ''
                while flag:
                    print("Enter operation number")
                    # Block till there is something on stdin or socket
                    inputready, outputready, exceptready = select.select(input, [], [])
                    for x in inputready:
                        if x == sock:
                            data = data + sock.recv(BYTES_READ)
                            if data == '' :
                                flag = False
                                break
                            data = data.split("|")
                            for i in range(0,len(data)-1):
                                cur_data = json.loads(data[i])
                                if cur_data['status'] == 0 :
                                    print('--------------------------------------------------------------------------------')
                                    print('operation code: ' + str(cur_data['operation']))
                                    print('operation status: failed')
                                    print('message: ' + cur_data['message'])
                                    print('--------------------------------------------------------------------------------')
                                elif cur_data['status'] == 1 :
                                    print('--------------------------------------------------------------------------------')
                                    print('operation code: ' + str(cur_data['operation']))
                                    print('operation status: success')
                                    print('message: ' + cur_data['message'])
                                    print('--------------------------------------------------------------------------------')
                                elif cur_data['status'] == 2 :
                                    print('--------------------------------------------------------------------------------')
                                    print('MESSAGE RECEIVED')
                                    print('operation code: ' + str(cur_data['operation']))
                                    print('sender: ' + cur_data['sender'])
                                    print('timestamp: ' + cur_data['timestamp'])
                                    print('message: ' + cur_data['message'])
                                    print('--------------------------------------------------------------------------------')
                            if data[-1] == '|' :
                                data = ''
                            else :
                                data = data[-1]
                        elif x == sys.stdin:
                            operation_selected = sys.stdin.readline()
                            if is_integer(operation_selected) :
                                operation_selected = int(operation_selected)
                                if operation_selected == 0:
                                    print_operation()
                                elif operation_selected == 1:
                                    signup_client(sock, operation_selected)
                                elif operation_selected == 2:
                                    login_client(sock, operation_selected)
                                elif operation_selected == 3:
                                    logout_client(sock, operation_selected)
                                    sock.close()
                                    flag = False
                                elif operation_selected == 4:
                                    users_online_client(sock, operation_selected)
                                elif operation_selected == 5:
                                    last_hour_login_users_client(sock, operation_selected)
                                elif operation_selected == 6:
                                    private_msg_client(sock, operation_selected)
                                elif operation_selected == 7:
                                    broadcast_client(sock, operation_selected)
                                elif operation_selected == 8:
                                    block_user_client(sock, operation_selected)
                                elif operation_selected == 9:
                                    unblock_user_client(sock, operation_selected)
                                else:
                                    print("Please enter a valid operation number")
                            else:
                                print("Please enter a valid integer")
                        else :
                            flag = False

            print 'Logged out!'
            os._exit(0)

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

def main():
    # Command line option parsing
    parser = optparse.OptionParser()
    parser.add_option(
        '-i', '--host', dest='host', help='Hostname or IP address')

    parser.add_option('-p', '--port', dest='port', type='int', help='Port')

    parser.add_option(
        '-c', '--child-num', dest='childnum', type='int', default=1,
        help='Number of children to spawn. Default is 5'
        )
    parser.add_option(
        '-t', '--con-num', dest='connum', type='int', default=1,
        help='Number of connections to establish. Default is 1'
        )

    options, args = parser.parse_args()

    if not (options.host and options.port):
        parser.print_help()
        sys.exit(1)

    # Function to take response from stdin and socket
    request(options.host, options.port,
            options.childnum, options.connum)

if __name__ == '__main__':
    main()
