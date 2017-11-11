<b>CHATAPP (CLIENT-SERVER CHAT MODEL)</b><br/>
This is a client-server messaging application. Clients communicate with each other using "commands" sent to centralized server.<br/><br/>
<b>How to run the application?</b><br/>
--> You need to have python 2.7 installed on your system.<br/>
--> For starting server: ''' python2 server.py --host <host_ip> --port <port_number> '''. Default host and port are 0.0.0.0 and 2000 respectively.<br/>
--> For starting client: ''' python2 client.py --host <ip_of_server> --port <port_number of server> '''.<br/> 

<b>Features:</b><br/>
--> Basic security features of a chat application.<br/>
--> Sever maintains text file with username password.<br/>&emsp;
	--> Clients authenticate themselves and log into the system.<br/>&emsp;
	--> After 3 consecutive unsuccessful login attempts, the servers blocks the Port of that IP for that user for 60 seconds. We don't block the whole IP as testing the application would be simpler if we block that port only.<br/>&emsp;
	--> Prohibit simultaneous duplicate logins.<br/>
--> Has support for broadcast and point to point messages.<br/>&emsp;
	--> Private messages: This message is sent only to a specific user(in real time) if the user is logged in otherwise it is stored in a file and sent as soon as the user logs in.<br/>&emsp;
	--> Broadcast message: This message is sent to all users(in real time) who are currently logged in and is stored in a file for users who are currentluy offline and is displayed to them as soon as they log in.<br/>
--> Supports asynchronous messaging: If a user is not available, such offline message are displayed when the user logs in next time.<br/>
--> Supports queries:<br/>&emsp;
	--> Display name of all online users.<br/>&emsp;
	--> Display names of users who are online and logged in within last hour.<br/>
--> Supports blocking/unblocking of users: The users can block and unblock other user(s). Based on this the private and croadcast messages will be delivered.<br/>
--> Logout and Signup functionality supported.<br/><br/>

<b>Implementation details:</b><br/>
A file './server_resources/user_pass.csv' maintains username and password for all users and clients authenticate themselves and log into the system. A file is created inside the directory ''' ./server_resources/user_data/ ''' by the name of the user who signs up. This file is used for storing messages when user is offline.<br/>&emsp;
	Server side:<br/>&emsp;&emsp;
		Helper function to signup users and checking information about existing users are:<br/>&emsp;&emsp;&emsp;
			'''is_user_auth(username, password)''' is for authentication.<br/>&emsp;&emsp;&emsp;
			'''signup_server(sock, data)''' is for sign-up part.<br/>&emsp;&emsp;&emsp;
			'''is_user_blocked_tmp(sock, username)''' is function to check if user is blocked.<br/>&emsp;&emsp;&emsp;
			'''add_user(username, password)''' is  function to add user to the database.<br/>&emsp;&emsp;&emsp;
			'''user_already_exists(username)''' is function to check user already exists in database.<br/>&emsp;&emsp;&emsp;
			'''is_user_blocked_tmp(sock, username)'''  function to check if user is blocked.<br/>&emsp;&emsp;&emsp;
			'''is_user_already_logged(username)''' function to check if user is authentic.<br/>&emsp;&emsp;&emsp;
			'''get_all_username()''' function to fetch all usernames.<br/>&emsp;&emsp;&emsp;
			'''username_exists(username)''' function to check if the username exists.<br/>&emsp;&emsp;&emsp;
			'''ip_port_already_used(sock)''' function to check if the port is already in use.<br/>&emsp;&emsp;&emsp;
			'''login_server(sock, data)''' function for login.<br/>&emsp;&emsp;&emsp;
			'''logout_server(sock, operation=-1) ''' function for logout.<br/>&emsp;&emsp;&emsp;
			'''is_user_logged_in(sock)''' function to check if user is logged in.<br/>&emsp;&emsp;&emsp;
			'''get_all_users_online()''' function to get all users online.<br/>&emsp;&emsp;&emsp;
			'''get_last_hour_login()'''  function to get all last hour logged in users.<br/>&emsp;&emsp;&emsp;
			'''users_online_server(sock, operation)''' function to check users online.<br/>&emsp;&emsp;&emsp;
			'''last_hour_login_users_server(sock, operation)''' to check last hour logged in users.<br/>&emsp;&emsp;&emsp;
			'''is_user_online(username)''' function to check if user is online.<br/>&emsp;&emsp;&emsp;
			'''get_username(sock)'''  function to get username.<br/>&emsp;&emsp;&emsp;
			'''get_sock(username)'''  function to get socket.<br/>&emsp;&emsp;&emsp;
			'''private_msg_server(sock, data)'''  function to send private message.<br/>&emsp;&emsp;
		For messaging and socket handling by threading :<br/>&emsp;&emsp;
		(Broadcast,Private message,Block and Unblock)<br/>&emsp;&emsp;&emsp;
			'''broadcast_server(sock, data)''' function for broadcast.<br/>&emsp;&emsp;&emsp;
			'''send_stored_msg(sock, data)''' function to send stored messages when user comes online.<br/>&emsp;&emsp;&emsp;
			'''handle(sock)''' is Main handler for incoming data.<br/>&emsp;&emsp;&emsp;
			'''child_loop(index, listen_sock)''' is function to create thread to make connections and serve client requests.<br/>&emsp;&emsp;&emsp;
			'''create_child(index, listen_sock)''' helper function to launch threads.<br/>&emsp;&emsp;&emsp;
			'''serve_forever(host, port, childnum)''' is helper function to create socket.<br/>&emsp;&emsp;&emsp;
			''' block_user_server(sock, data)'''  function to block user.<br/>&emsp;&emsp;&emsp;
			'''unblock_user_server(sock, data)''' function to unblock user.<br/><br/>&emsp;
	Client side:<br/>&emsp;&emsp;
		Following helper function are used for operations:<br/>&emsp;&emsp;&emsp;
			'''print_operation()''' is  helper function to print operations.<br/>&emsp;&emsp;&emsp;
			'''signup_client(sock, operation_selected)''' function for signup.<br/>&emsp;&emsp;&emsp;
			'''login_client(sock, operation_selected)''' function for login.<br/>&emsp;&emsp;&emsp;
			'''private_msg_client(sock, operation_selected)''' function for private messaging.<br/>&emsp;&emsp;&emsp;
			'''broadcast_client(sock, operation_selected)''' client helper function for broadcast.<br/>&emsp;&emsp;&emsp;
			'''block_user_client(sock, operation_selected)''' function to block user.<br/>&emsp;&emsp;&emsp;
			'''unblock_user_client(sock, operation_selected)''' function to unblock user.<br/>&emsp;&emsp;&emsp;
			'''logout_client(sock, operation_selected)''' function for logout.<br/>&emsp;&emsp;&emsp;
			'''last_hour_login_users_client(sock, operation_selected)''' function to check last hour logged in users.<br/>&emsp;&emsp;&emsp;
			'''is_integer(operation)''' function to check if the input is an integer.<br/>&emsp;&emsp;&emsp;
			'''request(host, port, child_num, con_num)''' spawn child_num children processes.<br/>&emsp;&emsp;&emsp;

