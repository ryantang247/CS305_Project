import socket
import base64
import os
from urllib.parse import urlparse, parse_qs, unquote
import hashlib
from datetime import datetime
import threading

from urlparser import UrlParser

account = {'client1': '123', 'client2': '123', 'client3': '123'}

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


session_storage = {}


def handle_login(username, password):
    # Validate username and password (your authentication logic)
    # If login successful:
    session_id = generate_unique_session_id(username)  # Generate a unique session ID
    session_storage[username] = session_id  # Store session ID for the user
    return session_id


def generate_unique_session_id(username):
    current_time = datetime.now().isoformat()  # Get current time as string
    # Concatenate username and current time for uniqueness

    data = f"{username}-{current_time}"

    # Use hashlib to hash the data (you can choose any hashing algorithm)
    hashed_data = hashlib.sha256(data.encode()).hexdigest()

    return hashed_data[:10]


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
        auth_header = headers.get("Authorization") or headers.get("authorization")

        if auth_header and auth_header.startswith("Basic "):
            encoded_credentials = auth_header.split(" ")[1]
            credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            print("credentials", credentials)
            # Replace this with your authentication logic
            username, password = credentials.split(":")

            # Check if the username exists in the account dictionary
            if username in account and account[username] == password:
                session_id = handle_login(username, password)
                return True, session_id, username
            else:
                return False

        return False
    except Exception as e:
        return False


def extractHeader(request_data):
    request_lines = request_data.split("\r\n")
    headers = {}
    print()
    for line in request_lines[1:]:
        if line:
            parts = line.split(":", 1)  # Split at the first occurrence of ":"
            if len(parts) == 2:
                key, value = parts
                headers[key.strip()] = value.strip()
            else:
                print(f"Ignoring invalid header line: {line}")
    return headers


def extractData(request_data):
    # Extract content length from headers
    headers = extractHeader(request_data)
    content_length = int(headers.get("Content-Length", 0))

    # Extract data from the request body
    data_start = request_data.find("\r\n\r\n") + 4  # Find the position where data starts
    data = request_data[data_start:data_start + content_length]

    return data


def get_key_from_value(dictionary, search_value):
    for key, value in dictionary.items():
        if value == search_value:
            return key
    return None


def isDeleteMethod(url):
    # Convert the URL to lowercase for case-insensitive comparison
    lowercase_url = url.lower()

    # Check if "delete" is present in the URL
    if "delete" in lowercase_url:
        return True
    else:
        return False


def handle_client_request(client_socket):
    # Receive data from the client
    # incr = 1;
    # while True:
    #     incr = incr + 1
    #     print("haha",incr)
    #     print(client_socket)
    username = None
    session_id = None
    request_data = client_socket.recv(2048).decode("utf-8")
    if not request_data:
        return "Bye"
    authenticated = None
    print(request_data)
    try:
        print('cookie', extractHeader(request_data)['Cookie'])
        if extractHeader(request_data)['Cookie']:
            username = get_key_from_value(session_storage, extractHeader(request_data)['Cookie'])
            if username is None:
                authenticated = authenticate(extractHeader(request_data))
                if not authenticated:
                    error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

                    client_socket.sendall(error_response.encode('utf-8'))
                    return
                session_id = authenticated[1]
                username = authenticated[2]
        else:
            print("user not yet auth")
            authenticated = authenticate(extractHeader(request_data))
            if not authenticated:
                error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

                client_socket.sendall(error_response.encode('utf-8'))
                return
            session_id = authenticated[1]
            username = authenticated[2]
    except Exception as e:
        print("exception on auth", e)
        authenticated = authenticate(extractHeader(request_data))
        if not authenticated:
            error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized Access"

            client_socket.sendall(error_response.encode('utf-8'))
            return
        session_id = authenticated[1]
        username = authenticated[2]
    # Parse HTTP request
    request_lines = request_data.split("\r\n")

    request_line = request_lines[0]
    print(request_line.split(" "))
    method, url, _ = request_line.split(" ")

    # Implement logic based on the HTTP method
    if method == "GET":

        req_type = UrlParser.process_url(url)
        formatted_url = url.lstrip('/').replace('/', os.path.sep)
        if req_type == 'download':
            # Send the HTML content as the response

            file_path = os.path.join(current_directory, "data", formatted_url)

            # Open the file in binary mode
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'rb') as file:
                    file_content = file.read()
                    content_length = len(file_content)
                    content_type = "application/octet-stream"  # Adjust content type based on the file

                    # Construct headers
                    headers = {
                        "Content-Length": str(content_length),
                        "Content-Type": content_type,
                        "Connection": "close",
                        "Set-Cookie": f"session_id={session_id}; HttpOnly; Path= /"
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

                    # Send the file content
                    client_socket.sendall(file_content)
            else:
                # If the file is not found, send a 404 response
                send_404(client_socket)

        elif req_type == 'chunktrans':

            # convert it to OS format
            url_without_param = UrlParser.parse_qs(url)['path'].lstrip('/').replace('/', os.path.sep)
            file_path = os.path.join(current_directory, "data", url_without_param)

            def send_chunked_data(client_socket, data):
                chunk = f"{len(data):X}\r\n{data.decode('utf-8')}\r\n"
                client_socket.sendall(chunk.encode('utf-8'))

            # Check if the file exists
            if os.path.exists(file_path):

                # Open and read the file content
                with open(file_path, 'rb') as file:
                    content = file.read()

                # Send the response headers
                headers = {
                    "HTTP/1.1": "200 OK",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/octet-stream",
                    "Connection": "open",
                    "Set-Cookie": f"session_id={session_id}; HttpOnly; Path= /"
                }
                response_header = ""
                for header, value in headers.items():
                    response_header += f"{header}: {value}\r\n"

                # Append an empty line to indicate the end of headers
                response_header += "\r\n"
                client_socket.sendall(response_header.encode('utf-8'))

                # Send the file content, in chunks

                for i in range(0, len(content), 1024):  # You can adjust the chunk size
                    send_chunked_data(client_socket, content[i:i + 1024])

                # ignore the last chunked data and see
                # send_chunked_data(client_socket, "")  # Send the final empty chunk

            else:
                send_404(client_socket)
        elif req_type == "view":

            url_parts = url.split('/')

            # Get the second part of the URL
            second_part = url_parts[1]
            path = os.path.join(current_directory, "data", second_part)
            files = get_file_list(path)

            # Render the HTML template with the file data
            html_content = generate_html(files)
            headers = {
                "Content-Length": str(len(html_content)),
                "Content-Type": "text/html",
                "Connection": "keep-alive",
                "Set-Cookie": f"session_id={session_id}; HttpOnly; Path= /"
            }
            response_status_line = "HTTP/1.1 200 OK\r\n"
            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"
            response_header += "\r\n"

            # Send the response status line, headers, and HTML content
            client_socket.sendall((response_status_line + response_header).encode('utf-8'))
            client_socket.sendall(html_content.encode('utf-8'))

        elif req_type == "home_page":
            path = os.path.join(current_directory, "login.html")
            with open(path, 'rb') as file:
                file_content = file.read()
                headers = {
                    "HTTP/1.1": "200 OK",
                    "Content-Length": str(len(file_content)),
                    "Content-Type": "text/html",  # Set the appropriate content type for HTML
                    "Connection": "open",
                    "Set-Cookie": f"session_id={session_id}; HttpOnly; Path= /"
                }

                response_header = ""
                for header, value in headers.items():
                    response_header += f"{header}: {value}\r\n"

                # Append an empty line to indicate the end of headers
                response_header += "\r\n"

                # Send the response header
                client_socket.sendall(response_header.encode('utf-8'))

                # Send the entire file content
                client_socket.sendall(file_content)

        elif req_type == "unknown":
            send_400(client_socket)
        else:
            send_400(client_socket)

    elif method == "HEAD":

        path = current_directory + url

        # Process as required for HEAD request

        if os.path.exists(path):  # Check if the requested resource exists

            # File exists, construct the headers

            headers = {
                "Content-Length": str(os.path.getsize(path)),  # Assuming file size is the content length for HEAD
                "Content-Type": "application/octet-stream",  # Modify as per your file type
                "Connection": "keep-alive",
                "Set-Cookie": f"session_id={session_id}; HttpOnly; Path=/",
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
            _headers = extractHeader(request_data)
            content_length = _headers.get("Content-Length")
            if content_length is None:
                # Content-Length header is defined in the headers
                error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length for POST"
                client_socket.sendall(error_response.encode('utf-8'))
                return
            content_length = int(_headers.get("Content-Length", 0))
            if (content_length == 0) and (isDeleteMethod(url=url) == False):
                # If Content-Length is specified as zero for POST, it's an invalid request
                error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length for POST"
                client_socket.sendall(error_response.encode('utf-8'))
                return  # Exit without processing further if invalid

            received_data = b""  # Initialize an empty byte string to store incoming data
            print("length: ", content_length)
            # Receive data until the full content is received based on the Content-Length

            data = extractData(request_data)
            # print("*** POST Data", data)
            while len(received_data) < content_length:
                received_data += data.encode()
                print(received_data)

            # Check for Authorization header

            response_body = "Data received successfully"
            headers = {
                "Content-Length": str(len(response_body)),
                "Content-Type": "text/plain",
                "Content-Disposition": _headers.get("Content-Disposition"),
                "Connection": "keep-alive",
                "Set-Cookie": f"session_id={session_id}; HttpOnly; Path= /"
            }
            response_status_line = None

            # Construct the response header
            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"

            # Append an empty line to indicate the end of headers
            response_header += "\r\n"

            # Send the response status line, headers, and response body
            # client_socket.sendall((response_status_line + response_header + response_body).encode('utf-8'))
            # print(process_url(url))
            if process_url(url=url) == 'upload':
                # Upload Method
                upload(client_socket=client_socket, url=url, received_data=received_data, username=username,
                       headers=headers)

            elif process_url(url=url) == 'delete':
                # Delete Method
                delete(client_socket=client_socket, url=url, received_data=received_data, username=username)

            else:
                # Authorization header not provided
                error_response = "HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization Required"
                client_socket.sendall(error_response.encode('utf-8'))

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            error_response = f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_message}"
            # print("****** Error: " + str(e) + "\n")
            client_socket.sendall(error_response.encode('utf-8'))

    else:
        # Return 405 Method Not Allowed for other methods
        error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\nIncorrect method used"
        client_socket.sendall(error_response.encode('utf-8'))
        # print(extractHeader(request_data))
        # if 'Connection' in extractHeader(request_data):
        #
        #     connection_header = headers['Connection'].lower()
        #     if connection_header == 'close':
        #         print("close")


def process_path(raw_path):
    # Unquote the path to handle percent-encoded characters
    unquoted_path = unquote(raw_path)

    # Remove leading and trailing slashes
    processed_path = unquoted_path.strip('/')

    return processed_path


def upload(client_socket, url, received_data, username, headers):
    # Extract query parameters using parse_qs
    query_params = parse_qs(urlparse(url).query)
    # print("****** Query Params: ", query_params)

    # Check for the "path" parameter in the query
    upload_path = query_params.get('path', [''])[0]
    if not upload_path:
        response_status_line = "HTTP/1.1 400 Bad Request\r\n\r\nMissing 'path' parameter in the query"
        client_socket.sendall(response_status_line.encode('utf-8'))
        return

    # Process the path using the new function
    upload_path = process_path(upload_path)

    # Check if the target directory exists
    target_directory = os.path.join(os.getcwd(), "data", upload_path)
    if not os.path.exists(target_directory):
        response_status_line = "HTTP/1.1 404 Not Found\r\n\r\nTarget directory does not exist"
        client_socket.sendall(response_status_line.encode('utf-8'))
        return

    if upload_path == username:
        # Extract the filename from the Content-Disposition header, if available
        content_disposition = headers.get("Content-Disposition")
        if content_disposition:
            # Manual parsing of Content-Disposition header
            params = [param.strip() for param in content_disposition.split(";")]
            filename_param = next((param for param in params if param.lower().startswith("filename")), None)

            if filename_param:
                _, filename = filename_param.split("=")
                filename = filename.strip("\"")
                filename = filename.strip("\'")
                file_path = os.path.join(target_directory, filename)
                with open(file_path, 'wb') as file:
                    file.write(received_data)

                # Respond with a success message
                response_status_line = "HTTP/1.1 200 OK\r\n\r\nFile uploaded successfully"
                client_socket.sendall(response_status_line.encode('utf-8'))
            else:
                response_status_line = "HTTP/1.1 400 Bad Request\r\n\r\nMissing 'filename' in Content-Disposition header"
                client_socket.sendall(response_status_line.encode('utf-8'))
        else:
            # Content-Disposition header not provided
            response_status_line = "HTTP/1.1 400 Bad Request\r\n\r\nContent-Disposition header missing"
            client_socket.sendall(response_status_line.encode('utf-8'))
    else:
        response_status_line = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to upload to this directory"
        client_socket.sendall(response_status_line.encode('utf-8'))


def delete(client_socket, url, received_data, username):
    # Extract query parameters using parse_qs
    query_params = parse_qs(urlparse(url).query)

    # Check for the "path" parameter in the query
    delete_path = query_params.get('path', [''])[0]
    print(delete_path)
    if not delete_path:
        error_response = "HTTP/1.1 400 Bad Request\r\n\r\nMissing 'path' parameter in the query"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    # Process the path using the new function
    delete_path = process_path(delete_path)

    # Check if the target file exists
    target_file = os.path.join(os.getcwd(), "data", delete_path)
    if not os.path.exists(target_file):
        error_response = "HTTP/1.1 404 Not Found\r\n\r\nTarget file does not exist"
        client_socket.sendall(error_response.encode('utf-8'))
        return

    if delete_path.startswith(username):
        # Ensure that the file is under the user's directory
        os.remove(target_file)

        # Respond with a success message
        success_response = "HTTP/1.1 200 OK\r\n\r\nFile deleted successfully"
        client_socket.sendall(success_response.encode('utf-8'))
    else:
        error_response = "HTTP/1.1 403 Forbidden\r\n\r\nYou don't have permission to delete this file"
        client_socket.sendall(error_response.encode('utf-8'))


def send_404(client_socket):
    response_body = 'File not found'
    headers = {
        "HTTP/1.1": "404 NOT FOUND",
        "Content-Length": len(response_body),
        "Content-Type": "text/plain",
        "Connection": "close",
    }
    response_header = ""
    for header, value in headers.items():
        response_header += f"{header} {value}\r\n"

    # Append an empty line to indicate the end of headers
    response_header += "\r\n"

    client_socket.sendall((response_header + response_body).encode('utf-8'))


def send_400(client_socket):
    response_body = 'Bad Request'
    headers = {
        "HTTP/1.1": "400 BAD REQUEST",
        "Content-Length": len(response_body),
        "Content-Type": "text/plain",
        "Connection": "close",
    }
    response_header = ""
    for header, value in headers.items():
        response_header += f"{header} {value}\r\n"

    # Append an empty line to indicate the end of headers
    response_header += "\r\n"

    client_socket.sendall((response_header + response_body).encode('utf-8'))


SERVER = '127.0.0.1'  # localhost
PORT = 8080  # Use a port number
# Listen for incoming connections, queue up to 5 requests
print("The server is ready to receive")


def client_thread(conn, addr):
    with conn:
        print(f"[CONNECTION] Connected to {addr}")
        while True:

            data = handle_client_request(conn)
            if data == "Bye" or data == None:
                break

    print(f"[CONNECTION] Disconnected from {addr}")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((SERVER, PORT))
    s.listen(5)
    print(f"[INFO] Listening on {SERVER}:{PORT}")

    while True:
        conn, addr = s.accept()
        print(f"[INFO] Starting thread for connection {addr}")
        thread = threading.Thread(target=client_thread, args=(conn, addr))
        thread.start()
