import socket
import base64

HOST = '127.0.0.1'  # localhost
PORT = 8080  # Use a port number

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)# Listen for incoming connections, queue up to 5 requests
print("The server is ready to receive")


def handle_client_request(client_socket):
    # Receive data from the client
    request_data = client_socket.recv(1024).decode("utf-8")
    print(request_data)
    # Parse HTTP request
    request_lines = request_data.split("\r\n")

    request_line = request_lines[0]

    method, url, _ = request_line.split(" ")


    # Implement logic based on the HTTP method
    if method == "GET":
        try:
            with open(url[1:], 'rb') as file:
                file_content = file.read()
                content_length = len(file_content)
                content_type = "text/plain"  # Adjust content type based on the file

                # Check for Authorization header
                auth_header = headers.get("Authorization")
                if auth_header and auth_header.startswith("Basic "):
                    # Extract and verify credentials
                    credentials_base64 = auth_header.split(" ")[1]
                    credentials = base64.b64decode(credentials_base64).decode('utf-8')

                    # Replace with your authentication logic
                    expected_credentials = "client1:123"  # Placeholder for expected credentials

                    if credentials == expected_credentials:
                        headers = {
                            "Content-Length": str(content_length),
                            "Content-Type": content_type,
                            "Connection": "close"
                        }
                        response_status_line = "HTTP/1.1 200 OK\r\n"
                        response_header = ""
                        for header, value in headers.items():
                            response_header += f"{header}: {value}\r\n"
                        response_header += "\r\n"

                        # Send the response status line, headers, and file content
                        client_socket.sendall((response_status_line + response_header).encode('utf-8'))
                        client_socket.sendall(file_content)
                    else:
                        # Unauthorized - incorrect credentials
                        error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"
                        client_socket.sendall(error_response.encode('utf-8'))
                else:
                    # Authorization header not provided
                    error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"
                    client_socket.sendall(error_response.encode('utf-8'))
        except FileNotFoundError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found"
            client_socket.sendall(error_response.encode('utf-8'))
        except Exception as e:
                error_message = f"An error occurred: {str(e)}"
                error_response = f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_message}"

                client_socket.sendall(error_response.encode('utf-8'))



    elif method == "HEAD":

        # Handle HEAD request - retrieve headers only

        # Similar to GET but without the response body

        try:
            print(url)
            print("get here",open(url, 'rb'))
            with open(url[1:], 'rb') as file:
                print("get here2")
                file_content = file.read()

                content_length = len(file_content)

                content_type = "text/plain"  # Adjust content type based on the file

                # Check for Authorization header

                auth_header = headers.get("Authorization")
                if auth_header and auth_header.startswith("Basic "):

                    # Extract credentials and decode base64
                    credentials_base64 = auth_header.split(" ")[1]

                    credentials = base64.b64decode(credentials_base64).decode('utf-8')
                    print(credentials)

                    # Now credentials will be in the format 'username:password'

                    # Verify credentials (this is a placeholder, replace it with your authentication logic)

                    expected_credentials = "client1:123"  # Placeholder for expected credentials

                    if credentials == expected_credentials:

                        # Construct headers

                        headers = {

                            "Content-Length": str(content_length),

                            "Content-Type": content_type,

                            "Connection": "close"

                        }

                        # Construct the response status line

                        response_status_line = "HTTP/1.1 200 OK\r\n"

                        # Construct the response header

                        response_header = ""

                        for header, value in headers.items():
                            response_header += f"{header}: {value}\r\n"

                        # Append an empty line to indicate the end of headers

                        response_header += "\r\n"

                        # Send the response status line and headers

                        client_socket.sendall((response_status_line + response_header).encode('utf-8'))

                        return  # Exit after sending headers without sending content

                    else:

                        # Unauthorized - incorrect credentials

                        error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

                        client_socket.sendall(error_response.encode('utf-8'))

                        return  # Exit without processing further if unauthorized

                else:

                    # Authorization header not provided

                    error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"

                    client_socket.sendall(error_response.encode('utf-8'))

        except FileNotFoundError:

            # Handle file not found error

            error_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found"

            client_socket.sendall(error_response.encode('utf-8'))


    elif method == "POST":

        # Handle POST request - receive data from the client
        try:
            content_length = headers.get("Content-Length")
            if content_length is None:
                # Content-Length header is defined in the headers
                error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length for POST"
                client_socket.sendall(error_response.encode('utf-8'))
                return
            content_length = int(headers.get("Content-Length", 0))
            if content_length == 0:
                # If Content-Length is specified as zero for POST, it's an invalid request
                error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length for POST"
                client_socket.sendall(error_response.encode('utf-8'))
                return  # Exit without processing further if invalid

            received_data = b""  # Initialize an empty byte string to store incoming data
            print("lengh",content_length)
            # Receive data until the full content is received based on the Content-Length

            while len(received_data) < content_length:
                received_data += client_socket.recv(1024)

            # Check for Authorization header

            auth_header = headers.get("Authorization")

            if auth_header and auth_header.startswith("Basic "):

                # Extract credentials and decode base64

                credentials_base64 = auth_header.split(" ")[1]

                credentials = base64.b64decode(credentials_base64).decode('utf-8')

                # Now credentials will be in the format 'username:password'

                # Verify credentials (this is a placeholder, replace it with your authentication logic)

                expected_credentials = "client1:123"  # Placeholder for expected credentials

                if credentials == expected_credentials:

                    # Process the received data (this is a placeholder, replace it with your processing logic)

                    # For example, if the data is a file being uploaded, you can save it on the server

                    # Replace this logic with what suits your application

                    # For demonstration purposes, let's print the received data

                    print("Received data:", received_data.decode('utf-8'))

                    # Construct headers and status code for the response

                    # Here, it just sends a simple success message as a response body

                    response_body = "Data received successfully"

                    headers = {

                        "Content-Length": str(len(response_body)),

                        "Content-Type": "text/plain",

                        "Connection": "close"

                    }

                    response_status_line = "HTTP/1.1 200 OK\r\n"

                    # Construct the response header

                    response_header = ""

                    for header, value in headers.items():
                        response_header += f"{header}: {value}\r\n"

                    # Append an empty line to indicate the end of headers

                    response_header += "\r\n"

                    # Send the response status line, headers, and response body

                    client_socket.sendall((response_status_line + response_header + response_body).encode('utf-8'))

                    return  # Exit after sending response

                else:

                    # Unauthorized - incorrect credentials

                    error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

                    client_socket.sendall(error_response.encode('utf-8'))

                    return  # Exit without processing further if unauthorized

            else:

                # Authorization header not provided

                error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"

                client_socket.sendall(error_response.encode('utf-8'))
        except Exception as e:
                error_message = f"An error occurred: {str(e)}"
                error_response = f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_message}"

                client_socket.sendall(error_response.encode('utf-8'))

while True:
    client_socket, client_address = server_socket.accept()
    handle_client_request(client_socket)
    client_socket.close()
