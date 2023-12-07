import socket
import base64
import os

HOST = '127.0.0.1'  # localhost
PORT = 8080  # Use a port number

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)  # Listen for incoming connections, queue up to 5 requests
print("The server is ready to receive")


def get_file_list(directory_path):
    try:
        # Get the list of files and directories in the specified path
        entries = os.listdir(directory_path)

        # Filter out directories, leaving only files
        files = [entry for entry in entries if os.path.isfile(os.path.join(directory_path, entry))]

        return files
    except OSError as e:
        # Handle any potential errors, such as permission issues or non-existent directories
        print(f"Error while getting file list: {e}")
        return []

def generate_html(file_list):
    html_content = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n"
    html_content += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    html_content += "<title>File List</title>\n</head>\n<body>\n"
    html_content += "<h1>File List</h1>\n<ul>\n"

    for file_name in file_list:
        html_content += f"    <li>{file_name}</li>\n"

    html_content += "</ul>\n</body>\n</html>"

    return html_content

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
        if url == "/":
            directory_path = r"C:\Users\Asus\Desktop\Computer Networks\CS305_Project\CS305_Project"  # Using a raw string
            files = get_file_list(directory_path)

            # Render the HTML template with the file data
            html_content = generate_html(files)

            # Send the HTML content as the response
            headers = {
                "Content-Length": str(len(html_content)),
                "Content-Type": "text/html",
                "Connection": "close"
            }
            response_status_line = "HTTP/1.1 200 OK\r\n"
            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"
            response_header += "\r\n"

            # Send the response status line, headers, and HTML content
            client_socket.sendall((response_status_line + response_header).encode('utf-8'))
            client_socket.sendall(html_content.encode('utf-8'))
        elif url.startswith("/files"):
            handle_file_request(client_socket, url)
        else:
            error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"
            client_socket.sendall(error_response.encode('utf-8'))
        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            error_response = f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_message}"

            client_socket.sendall(error_response.encode('utf-8'))


    # # Ensure each user has their own directory
    # auth_header = headers.get("Authorization")
    # if auth_header and auth_header.startswith("Basic "):
    #     credentials_base64 = auth_header.split(" ")[1]
    #     credentials = base64.b64decode(credentials_base64).decode('utf-8')
    #     username, _ = credentials.split(":")
    #
    #     # Check if the user has permission to upload in their own directory
    #     if username not in allowed_users:
    #         error_response = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to upload files"
    #         client_socket.sendall(error_response.encode('utf-8'))
    #         return
    #
    #     # Create user directory if it doesn't exist
    #     user_directory = os.path.join(os.getcwd(), "data", username)
    #     if not os.path.exists(user_directory):
    #         os.makedirs(user_directory)
    #
    #     # Ensure that users can only access their own directories
    #     if username not in allowed_users:
    #         error_response = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to access this directory"
    #         client_socket.sendall(error_response.encode('utf-8'))
    #         return
    #
    # # Parse HTTP request
    # request_lines = request_data.split("\r\n")
    # request_line = request_lines[0]
    # method, url, _ = request_line.split(" ")

    elif method == "HEAD":

        # Handle HEAD request - retrieve headers only

        # Similar to GET but without the response body

        try:

            with open(url[1:], 'rb') as file:

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
            print("lengh", content_length)
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

                    # Upload Method
                    upload(client_socket=client_socket, url=url, received_data=received_data)

                    # Delete Method
                    delete(client_socket=client_socket, url=url, received_data=received_data)


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

    else:
        # Return 405 Method Not Allowed for other methods
        error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly POST method is allowed for file upload"
        client_socket.sendall(error_response.encode('utf-8'))


def upload(client_socket, url, received_data):
    # Extract query parameters
    query_params = {}
    if "?" in url:
        path_param = url.split("?")[1]
        path_param = path_param.split("&")
        for param in path_param:
            key, value = param.split("=")
            query_params[key] = value

    # Check for the "path" parameter in the query
    upload_path = query_params.get('path')
    if not upload_path:
        error_response = "HTTP/1.1 400 Bad Request\r\n\r\nMissing 'path' parameter in the query"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    # Check if the target directory exists
    target_directory = os.path.join(os.getcwd(), "data", upload_path)
    if not os.path.exists(target_directory):
        error_response = "HTTP/1.1 404 Not Found\r\n\r\nTarget directory does not exist"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    # Check if the user has permission to upload in the target directory
    auth_header = headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        credentials_base64 = auth_header.split(" ")[1]
        credentials = base64.b64decode(credentials_base64).decode('utf-8')
        username, _ = credentials.split(":")

        if username == "11912113" and upload_path.startswith(username):
            # Save the uploaded file in the target directory
            file_path = os.path.join(target_directory, os.path.basename(url[1:]))
            with open(file_path, 'wb') as file:
                file.write(received_data)

            # Respond with a success message
            success_response = "HTTP/1.1 200 OK\r\n\r\nFile uploaded successfully"
            client_socket.sendall(success_response.encode('utf-8'))
        else:
            error_response = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to upload to this directory"
            client_socket.sendall(error_response.encode('utf-8'))
    else:
        # Authorization header not provided
        error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"
        client_socket.sendall(error_response.encode('utf-8'))




def delete(client_socket, url, received_data):
    # Extract query parameters
    query_params = {}
    if "?" in url:
        path_param = url.split("?")[1]
        path_param = path_param.split("&")
        for param in path_param:
            key, value = param.split("=")
            query_params[key] = value

    # Check for the "path" parameter in the query
    delete_path = query_params.get('path')
    if not delete_path:
        error_response = "HTTP/1.1 400 Bad Request\r\n\r\nMissing 'path' parameter in the query"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    # Check if the target file exists
    target_file = os.path.join(os.getcwd(), "data", delete_path)
    if not os.path.exists(target_file):
        error_response = "HTTP/1.1 404 Not Found\r\n\r\nTarget file does not exist"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    # Check if the user has permission to delete the target file
    auth_header = headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        credentials_base64 = auth_header.split(" ")[1]
        credentials = base64.b64decode(credentials_base64).decode('utf-8')
        username, _ = credentials.split(":")

        if username == "11912113" and delete_path.startswith(username):
            # Ensure that the file is under the user's directory
            os.remove(target_file)
            # Respond with a success message
            success_response = "HTTP/1.1 200 OK\r\n\r\nFile deleted successfully"
            client_socket.sendall(success_response.encode('utf-8'))
        else:
            error_response = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to delete this file"
            client_socket.sendall(error_response.encode('utf-8'))
    else:
        # Authorization header not provided
        error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"
        client_socket.sendall(error_response.encode('utf-8'))


while True:
    client_socket, client_address = server_socket.accept()
    handle_client_request(client_socket)
    client_socket.close()


