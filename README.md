CHATAPP (CLIENT-SERVER CHAT MODEL)

This is a client-server messaging application. Clients communicate with each other using "commands" sent to centralized server. 

How to run the application?
	--> You need to have python 2.7 installed on your system.
	--> For starting server: ''' python2 server.py --host <host_ip> --port <port_number> '''. Default host and port are 0.0.0.0 and 2000 respectively
	--> For starting client: ''' python2 client.py --host <ip_of_server> --port <port_number of server> '''. 

Features:
--> Basic security features of a chat application.
	--> Sever maintains text file with username password.
	--> Clients authenticate themselves and log into the system.
	--> After 3 consecutive unsuccessful login attempts, the servers blocks the Port of that IP for that user for 60 seconds. We don't block the whole IP as testing the application would be simpler if we block that port only.
	--> Prohibit simultaneous duplicate logins.
--> Has support for broadcast and point to point messages.
	--> Private messages: This message is sent only to a specific user(in real time) if the user is logged in otherwise it is stored in a file and sent as soon as the user logs in.
	--> Broadcast message: This message is sent to all users(in real time) who are currently logged in and is stored in a file for users who are currentluy offline and is displayed to them as soon as they log in.
--> Supports asynchronous messaging: If a user is not available, such offline message are displayed when the user logs in next time.
--> Supports queries:
	--> Display name of all online users.
	--> Display names of users who are online and logged in within last hour.
--> Supports blocking/unblocking of users: The users can block and unblock other user(s). Based on this the private and croadcast messages will be delivered.
--> Logout and Signup functionality supported.

Implementation details:
A file './server_resources/user_pass.csv' maintains username and password for all users and clients authenticate themselves and log into the system. A file is created inside the directory ''' ./server_resources/user_data/ ''' by the name of the user who signs up. This file is used for storing messages when user is offline.
	Server side:
		Helper function to signup users and checking information about existing users are:
			'''is_user_auth(username, password)''' is for authentication
			'''signup_server(sock, data)''' is for sign-up part.
			'''is_user_blocked_tmp(sock, username)''' is function to check if user is blocked.
			'''add_user(username, password)''' is  function to add user to the database.
			'''user_already_exists(username)''' is function to check user already exists in database.
			'''is_user_blocked_tmp(sock, username)'''  function to check if user is blocked.
			'''is_user_already_logged(username)''' function to check if user is authentic.
			'''get_all_username()''' function to fetch all usernames.
			'''username_exists(username)''' function to check if the username exists.
			'''ip_port_already_used(sock)''' function to check if the port is already in use.
			'''login_server(sock, data)''' function for login.
			'''logout_server(sock, operation=-1) ''' function for logout.
			'''is_user_logged_in(sock)''' function to check if user is logged in.
			'''get_all_users_online()''' function to get all users online.
			'''get_last_hour_login()'''  function to get all last hour logged in users.
			'''users_online_server(sock, operation)''' function to check users online.
			'''last_hour_login_users_server(sock, operation)''' to check last hour logged in users.
			'''is_user_online(username)''' function to check if user is online.
			'''get_username(sock)'''  function to get username.
			'''get_sock(username)'''  function to get socket.
			'''private_msg_server(sock, data)'''  function to send private message.
		For messaging and socket handling by threading :
		(Broadcast,Private message,Block and Unblock)
			'''broadcast_server(sock, data)''' function for broadcast.
			'''send_stored_msg(sock, data)''' function to send stored messages when user comes online.
			'''handle(sock)''' is Main handler for incoming data.
			'''child_loop(index, listen_sock)''' is function to create thread to make connections and serve client requests.
			'''create_child(index, listen_sock)''' helper function to launch threads.
			'''serve_forever(host, port, childnum)''' is helper function to create socket.
			''' block_user_server(sock, data)'''  function to block user.
			'''unblock_user_server(sock, data)''' function to unblock user.

	Client side:
		Following helper function are used for operations:
			'''print_operation()''' is  helper function to print operations.
			'''signup_client(sock, operation_selected)''' function for signup.
			'''login_client(sock, operation_selected)''' function for login.
			'''private_msg_client(sock, operation_selected)''' function for private messaging.
			'''broadcast_client(sock, operation_selected)''' client helper function for broadcast.
			'''block_user_client(sock, operation_selected)''' function to block user.
			'''unblock_user_client(sock, operation_selected)''' function to unblock user.
			'''logout_client(sock, operation_selected)''' function for logout.
			'''last_hour_login_users_client(sock, operation_selected)''' function to check last hour logged in users.
			'''is_integer(operation)''' function to check if the input is an integer.
			'''request(host, port, child_num, con_num)''' spawn child_num children processes.

