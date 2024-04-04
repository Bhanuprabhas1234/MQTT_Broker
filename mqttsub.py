import socket
import ssl

def signup_or_login():
    choice = input("Do you want to (S)ignup or (L)ogin? ").upper()
    if choice == "S":
        return "SIGNUP"
    elif choice == "L":
        return "LOGIN"
    else:
        print("Invalid choice. Please try again.")
        return signup_or_login()

def main():
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Wrap the client socket with SSL
        ssl_client_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLS)
        
        ssl_client_socket.connect(("192.168.176.40", 12559))
        print("Connected to server.")

        # Specify client action as signup or login
        ssl_client_socket.sendall(signup_or_login().encode())

        # Send username and password
        username = input("Enter username: ")
        password = input("Enter password: ")

        ssl_client_socket.sendall(username.encode())
        ssl_client_socket.sendall(password.encode())

        # Authenticate as subscriber
        client_type = "SUBSCRIBER"
        ssl_client_socket.sendall(client_type.encode())

        response = ssl_client_socket.recv(1024).decode()
        print(response)

        if response == "Signup successful." or response == "Login successful.":
            while True:
                try:
                    choice = input("Do you want to (S)ubscribe to a topic, (L)ist available topics, or (Q)uit? ").upper()
                    if choice == "S":
                        topic = input("Enter topic to subscribe to: ")
                        ssl_client_socket.sendall(f"SUBSCRIBE:{topic}".encode())

                        # Receive messages for the topic
                        response = ssl_client_socket.recv(1024).decode()
                        print(f"Messages for topic '{topic}':")
                        print(response)

                        # Receive SUBACK message to acknowledge receipt of messages (QoS 0)
                        suback = ssl_client_socket.recv(1024).decode()
                        print(f"Received SUBACK message: {suback}")
                    elif choice == "L":
                        ssl_client_socket.sendall("SUBSCRIBE:LIST_TOPICS".encode())

                        # Receive list of topics from server
                        response = ssl_client_socket.recv(1024).decode()
                        print("Available topics:")
                        print(response)

                        # Receive SUBACK message to acknowledge receipt of messages (QoS 0)
                        suback = ssl_client_socket.recv(1024).decode()
                        print(f"Received SUBACK message: {suback}")
                    elif choice == "Q":
                        break
                    else:
                        print("Invalid choice. Please try again.")

                except Exception as e:
                    print(f"Error occurred: {e}")
                    ssl_client_socket.close()
                    break
        else:
            print("Authentication failed.")

        # Close client socket when done
        ssl_client_socket.close()
        print("Connection closed.")
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()