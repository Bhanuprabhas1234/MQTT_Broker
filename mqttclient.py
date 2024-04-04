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
        
        ssl_client_socket.connect(("10.5.25.161", 12559))
        print("Connected to server.")

        # Specify client action as signup or login
        ssl_client_socket.sendall(signup_or_login().encode())

        # Send username and password
        username = input("Enter username: ")
        password = input("Enter password: ")

        ssl_client_socket.sendall(username.encode())
        ssl_client_socket.sendall(password.encode())

        # Authenticate as publisher
        client_type = "PUBLISHER"
        ssl_client_socket.sendall(client_type.encode())

        response = ssl_client_socket.recv(1024).decode()
        print(response)

        if response == "Signup successful." or response == "Login successful.":
            while True:
                try:
                    topic = input("Enter topic: ")
                    message = input("Enter message: ")

                    # Send PUBLISH command
                    data = f"PUBLISH:{topic},{message}"
                    ssl_client_socket.sendall(data.encode())
                    print("Message published successfully!")

                    # Receive PUBACK message to acknowledge message reception by the server (QoS 0)
                    puback = ssl_client_socket.recv(1024).decode()
                    print(f"Received PUBACK message: {puback}")

                    # Ask user if they want to publish again
                    choice = input("Do you want to publish again? (yes/no): ")
                    if choice.lower() != "yes":
                        break
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