import os
import sys
import json
import errno
import socket
import optparse

BYTES_READ = 3000

def print_operation():
    print("0 | List of options")
    print("1 | Sign up")
    print("2 | Log in")

def signup_client(sock, operation_selected):
    username=raw_input('Enter username: ')
    password = raw_input('Enter password: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
        'password': password
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)
    data = sock.recv(BYTES_READ)
    data = json.loads(data)
    print("data: ", data)
    if data['status'] == 0 :
        print('Your operation failed with following message from server: %s' %data['message'])
    else:
        print('Operation succeeded with following message from server: %s' %data['message'])

def login_client(sock, operation_selected):
    username=raw_input('Enter username: ')
    password = raw_input('Enter password: ')
    dict_to_send = {
        'operation': operation_selected,
        'username': username,
        'password': password
    }
    dict_to_send = json.dumps(dict_to_send)
    sock.sendall(dict_to_send)
    data = sock.recv(BYTES_READ)
    data = json.loads(data)
    print("data: ", data)
    if data['status'] == 0 :
        print('Your operation failed with following message from server: %s' %data['message'])
    else:
        print('Operation succeeded with following message from server: %s' %data['message'])

def is_integer(operation):
    try: 
        int(operation)
        return True
    except ValueError:
        return False

def request(host, port, child_num, con_num, bytes):
    # spawn child_num children processes
    for cnum in range(child_num):

        pid = os.fork()
        if pid == 0: # child

            for i in range(con_num):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                
                # 1st time
                flag = True
                print_operation();
                while flag:
                    # sock.sendall("test2")
                    # data = sock.recv(BYTES_READ)
                    # print data
                    print("Enter operation number")
                    operation_selected = raw_input()
                    if is_integer(operation_selected) :
                        operation_selected = int(operation_selected)
                        if operation_selected == 0:
                            print_operation()
                        elif operation_selected == 1:
                            signup_client(sock, operation_selected)
                            flag = False
                        elif operation_selected == 2:
                            login_client(sock, operation_selected)
                            flag = False
                        else:
                            print("Please enter a valid operation number")
                    else:
                        print("Please enter a valid integer")

                sock.close() # TIME_WAIT state on the client

            print 'Child %d is done' % cnum
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
        help='Number of connections to establish. Default is 5'
        )
    parser.add_option(
        '-b', '--bytes', dest='bytes', type='int', default=3000,
        help='Number of bytes to request. Default is 3000'
        )

    options, args = parser.parse_args()

    if not (options.host and options.port):
        parser.print_help()
        sys.exit(1)

    request(options.host, options.port,
            options.childnum, options.connum, options.bytes)

if __name__ == '__main__':
    main()