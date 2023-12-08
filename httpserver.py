import socket
import base64
import os
from urllib.parse import parse_qs, urlparse
account = {'client1': '123'}
HOST = '127.0.0.1'  # localhost
PORT = 8080  # Use a port number

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(100)# Listen for incoming connections, queue up to 5 requests
print("The server is ready to receive")

current_directory = os.path.dirname(os.path.abspath(__file__))

print(f"The directory of the current file is: {current_directory}")
def process_url(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Extract the path and query parameters
    path = parsed_url.path.strip("/")
    query_params = parse_qs(parsed_url.query)

    # Check for the existence of certain keywords in the path or query parameters
    if path.startswith("delete"):
        # This is an upload/delete type URL
        operation_type = "delete"
        # file_path = query_params.get("path", [])[0]  # Extract the file path from the query parameters
    elif path.startswith("upload"):
        operation_type = "upload"
    elif path and len(path.split("/")) == 2:
        # This is a valid download type URL with both {name} and {file_name} segments
        operation_type = "download"
    elif "SUSTech-HTTP" in query_params:
        # This is a view type URL
        operation_type = "view"
    else:
        # Unknown or unsupported URL type
        operation_type = "unknown"

    return operation_type


def extract_name_from_url(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Extract the path
    path = parsed_url.path.strip("/")

    # Split the path by "/" and get the second segment
    path_segments = path.split("/")

    # Check if there are at least 1 segments (may need modify)
    if len(path_segments) >= 1:
        # Extract the second segment, which is the {name} part
        name = path_segments[0]
        return name
    else:
        # Return None or raise an exception based on your specific requirement
        return None

def extract_file_from_url(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Extract the path
    path = parsed_url.path.strip("/")

    # Split the path by "/" and get the second segment
    path_segments = path.split("/")

    # Check if there are at least 1 segments (may need modify)
    if len(path_segments) >= 2:
        # Extract the second segment, which is the {name} part
        name = path_segments[1]
        return name
    else:
        # Return None or raise an exception based on your specific requirement
        return None

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
# def authentication():

def generate_html(file_list):
    html_content = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n"
    html_content += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    html_content += "<title>File List</title>\n</head>\n<body>\n"
    html_content += "<h1>File List</h1>\n<ul>\n"

    for file_name in file_list:
        html_content += f"    <li>{file_name}</li>\n"

    html_content += "</ul>\n</body>\n</html>"

    return html_content
def authenticate(headers):
    try:
        auth_header = headers.get("Authorization")


        if auth_header and auth_header.startswith("Basic "):
            encoded_credentials = auth_header.split(" ")[1]
            credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            print("credentials",credentials)
            # Replace this with your authentication logic
            username, password = credentials.split(":")

            # Check if the username exists in the account dictionary
            if username in account and account[username] == password:
                return True
            else:
                return False

        return False
    except Exception as e:
        return False
def extractHeader(request_data):
    request_lines = request_data.split("\r\n")
    headers = {}
    for line in request_lines[1:]:
        if line:
            key, value = line.split(":", 1)  # Split at the first occurrence of ":"
            headers[key.strip()] = value.strip()
    return headers
def handle_client_request(client_socket):
    # Receive data from the client
    request_data = client_socket.recv(1024).decode("utf-8")
    print(request_data)

    authenticated = authenticate(extractHeader(request_data))
    if(authenticated == False):
        error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

        client_socket.sendall(error_response.encode('utf-8'))
        return
    # Parse HTTP request
    request_lines = request_data.split("\r\n")

    request_line = request_lines[0]
    print(request_line.split(" "))
    method, url, _ = request_line.split(" ")





    # Implement logic based on the HTTP method
    if method == "GET":

        path = current_directory + url;
        # if url == "/":
               # Using a raw string
        files = get_file_list(path)

        # Render the HTML template with the file data
        html_content = generate_html(files)

        # Send the HTML content as the response
        headers = {
            "Content-Length": str(len(html_content)),
            "Content-Type": "text/html",
            "Connection": "keep-alive"
        }
        response_status_line = "HTTP/1.1 200 OK\r\n"
        response_header = ""
        for header, value in headers.items():
            response_header += f"{header}: {value}\r\n"
        response_header += "\r\n"

        # Send the response status line, headers, and HTML content
        client_socket.sendall((response_status_line + response_header).encode('utf-8'))
        client_socket.sendall(html_content.encode('utf-8'))
        # elif url.startswith("/files"):
        #     handle_file_request(client_socket, url)
        # else:
        #     error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"
        #     client_socket.sendall(error_response.encode('utf-8'))

    if method == "HEAD":

        path = current_directory + url

        # Process as required for HEAD request

        if os.path.exists(path):  # Check if the requested resource exists

            # File exists, construct the headers

            headers = {

                "Content-Length": str(os.path.getsize(path)),  # Assuming file size is the content length for HEAD

                "Content-Type": "application/octet-stream",  # Modify as per your file type

                "Connection": "keep-alive"

            }

            response_status_line = "HTTP/1.1 200 OK\r\n"

            response_header = ""

            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"

            response_header += "\r\n"

            # Send the response status line and headers (without body)

            client_socket.sendall((response_status_line + response_header).encode('utf-8'))

        else:

            # File doesn't exist, handle accordingly with a 404 Not Found response

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

                        "Connection": "keep-alive"

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
client_thread = []
while True:
    client_socket, client_address = server_socket.accept()
    # client_thread.append(client_socket)
    # print(f"User {client_socket} joined")
    handle_client_request(client_socket)
    client_socket.close();
    # print("user left")

