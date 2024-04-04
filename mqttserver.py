import socket
import threading
import ssl

# Dictionary to store topic messages
topic_messages = {}

# Dictionary to store user credentials (username: password)
user_credentials = {}

# Dictionary to store authenticated sessions (socket: username)
authenticated_sessions = {}

# List to store active subscribers
active_subscribers = []

# List to store active publishers
active_publishers = []

# List of available topics
topics = []

# Function to handle publisher connections
def handle_publisher(client_socket, username):
    publisher_address = client_socket.getpeername()
    active_publishers.append(publisher_address)
    print(f"Publisher connected: {publisher_address}")

    while True:
        try:
            # Receive data from publisher
            data = client_socket.recv(1024)
            if not data:
                break

            # Process data
            parts = data.decode().split(':')
            if len(parts) != 2:
                print("Invalid message format.")
                continue

            command, content = parts
            if command == "PUBLISH":
                topic, message = content.split(',')
                if topic not in topic_messages:
                    topic_messages[topic] = []
                    topics.append(topic)
                if message not in topic_messages[topic]:  # Check if message already exists
                    topic_messages[topic].append(message)
                    print(f"Published message to topic '{topic}': {message}")
                else:
                    print(f"Message already exists for topic '{topic}': {message}")

                # Send PUBACK to acknowledge message reception by the server (QoS 0)
                client_socket.sendall("PUBACK".encode())
            else:
                print("Invalid command for a publisher.")
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Error occurred: {e}")
            break

    # Close publisher socket
    client_socket.close()
    active_publishers.remove(publisher_address)
    print(f"Publisher disconnected: {publisher_address}")

# Function to handle subscriber connections
def handle_subscriber(client_socket, username):
    subscriber_address = client_socket.getpeername()
    active_subscribers.append(subscriber_address)
    print(f"Subscriber connected: {subscriber_address}")

    while True:
        try:
            # Receive data from subscriber
            data = client_socket.recv(1024)
            if not data:
                break

            # Process data
            parts = data.decode().split(':')
            if len(parts) != 2:
                print("Invalid message format.")
                continue

            command, content = parts
            if command == "SUBSCRIBE":
                if content == "LIST_TOPICS":
                    client_socket.sendall("\n".join(topics).encode())
                elif content in topic_messages:
                    messages = topic_messages[content]
                    client_socket.sendall("\n".join(messages).encode())
                else:
                    client_socket.sendall("No messages for this topic.".encode())

                # Send SUBACK to acknowledge receipt of messages (QoS 0)
                client_socket.sendall("SUBACK".encode())
            else:
                print("Invalid command for a subscriber.")
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Error occurred: {e}")
            break

    # Close subscriber socket
    client_socket.close()
    active_subscribers.remove(subscriber_address)
    print(f"Subscriber disconnected: {subscriber_address}")

# Function to handle signup process
def handle_signup(client_socket):
    try:
        # Receive client's username and password
        username = client_socket.recv(1024).decode()
        password = client_socket.recv(1024).decode()

        # Add new user credentials
        user_credentials[username] = password

        # Store authenticated session for publisher
        authenticated_sessions[client_socket] = username

        # Send confirmation message
        client_socket.sendall("Signup successful.".encode())

        # Determine whether the client is a publisher or a subscriber
        client_type = client_socket.recv(1024).decode()
        if client_type == "PUBLISHER":
            # Handle publisher connection in a separate thread
            publisher_thread = threading.Thread(target=handle_publisher, args=(client_socket, username))
            publisher_thread.start()
        elif client_type == "SUBSCRIBER":
            # Handle subscriber connection in a separate thread
            subscriber_thread = threading.Thread(target=handle_subscriber, args=(client_socket, username))
            subscriber_thread.start()
        else:
            print("Unknown client type.")

    except Exception as e:
        print(f"Error occurred during signup: {e}")
        client_socket.sendall("Signup failed.".encode())
        client_socket.close()

# Function to handle login process
def handle_login(client_socket):
    try:
        # Receive client's username and password
        username = client_socket.recv(1024).decode()
        password = client_socket.recv(1024).decode()

        # Validate credentials
        if username in user_credentials and user_credentials[username] == password:
            # Authentication successful, store authenticated session
            authenticated_sessions[client_socket] = username

            # Send confirmation message
            client_socket.sendall("Login successful.".encode())

            # Determine whether the client is a publisher or a subscriber
            client_type = client_socket.recv(1024).decode()
            if client_type == "PUBLISHER":
                # Handle publisher connection in a separate thread
                publisher_thread = threading.Thread(target=handle_publisher, args=(client_socket, username))
                publisher_thread.start()
            elif client_type == "SUBSCRIBER":
                # Handle subscriber connection in a separate thread
                subscriber_thread = threading.Thread(target=handle_subscriber, args=(client_socket, username))
                subscriber_thread.start()
            else:
                print("Unknown client type.")
        else:
            # Authentication failed, send failure message
            client_socket.sendall("Login failed.".encode())
            client_socket.close()

    except Exception as e:
        print(f"Error occurred during login: {e}")
        client_socket.sendall("Login failed.".encode())
        client_socket.close()

# Function to start the SSL server
def start_ssl_server():
    try:
        # Create a TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("192.168.176.40", 12559))
        server_socket.listen(5)
        print("Server started and listening on port 8888...")

        while True:
            # Accept incoming client connection
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr[0]}:{addr[1]}")

            # Wrap the client socket with SSL
            ssl_client_socket = ssl.wrap_socket(client_socket, server_side=True, certfile="server.crt", keyfile="server.key", ssl_version=ssl.PROTOCOL_TLS)

            # Determine whether the client wants to signup or login
            action = ssl_client_socket.recv(1024).decode()
            if action == "SIGNUP":
                # Handle signup process
                handle_signup(ssl_client_socket)
            elif action == "LOGIN":
                # Handle login process
                handle_login(ssl_client_socket)
            else:
                print("Unknown action.")

    except Exception as e:
        print(f"Error occurred: {e}")

# Start the SSL server
start_ssl_server()