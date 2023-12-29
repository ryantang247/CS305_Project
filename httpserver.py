from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import base64
import os
from urllib.parse import urlparse, parse_qs, unquote
from view_download import ViewDownload
from urlparser import UrlParser
import hashlib
from datetime import datetime
import threading
import json
import rsa
import time

account = {'client1': '123', 'client2': '123', 'client3': '123'}
publicKey, privateKey = rsa.newkeys(512)
current_directory = os.path.dirname(os.path.abspath(__file__))

print(f"The directory of the current file is: {current_directory}")

session_keys = {}


# Function to handle new client connections


def clear_session_keys():
    global session_keys
    while True:
        time.sleep(300)  # Sleep for 5 minutes (300 seconds)
        session_keys = {}  # Clear the dictionary


# Start a separate thread to clear the session_keys
clear_keys_thread = threading.Thread(target=clear_session_keys)
clear_keys_thread.daemon = True  # Set the thread as a daemon so it exits when the main program ends
clear_keys_thread.start()


# Function to handle client disconnection


def handle_client_disconnection(session_id):
    # Remove the key associated with the session ID upon disconnection
    if session_id in session_keys:
        del session_keys[session_id]


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


session_storage = {}


def handle_login(username, password):
    # Validate username and password (your authentication logic)
    # If login successful:
    session_id = generate_unique_session_id(
        username)  # Generate a unique session ID
    session_storage[username] = session_id  # Store session ID for the user
    return session_id


def generate_unique_session_id(username):
    current_time = datetime.now().isoformat()  # Get current time as string
    # Concatenate username and current time for uniqueness

    data = f"{username}-{current_time}"

    # Use hashlib to hash the data (you can choose any hashing algorithm)
    hashed_data = hashlib.sha256(data.encode()).hexdigest()

    return hashed_data[:10]


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
    # Find the position where data starts
    data_start = request_data.find("\r\n\r\n") + 4
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


def symmetric_decrypt(encrypted_data, key, iv):
    # Convert the key and IV into bytes if they're not already in bytes format
    key = key.encode() if isinstance(key, str) else key
    iv = iv.encode() if isinstance(iv, str) else iv

    # Ensure the key is 16, 24, or 32 bytes long (AES-128, AES-192, or AES-256)
    if len(key) not in [16, 24, 32]:
        raise ValueError(
            "Key must be 16, 24, or 32 bytes long for AES decryption")

    # Create an AES cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())

    # Create a decryptor
    decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data


def receive_larger(client_socket, buffer_size=4096):
    received_data = b""
    while True:
        chunk = client_socket.recv(buffer_size)
        if not chunk:
            break
        received_data += chunk
        if len(chunk) < buffer_size:
            # Break the loop if the received chunk is less than the buffer size, indicating the end of the data
            break
    return received_data


def process_request_data(client_socket):
    received_data = receive_larger(client_socket)
    result_data = None
    try:
        # Try to decode the received data as UTF-8
        result_data = received_data.decode("utf-8")
        # Your text data processing logic here

    except UnicodeDecodeError:
        # If decoding as UTF-8 fails, assume it's binary data
        # You can use base64 encoding to handle binary data
        result_data = base64.b64encode(received_data).decode("utf-8")
        # Your binary data processing logic here

    return result_data


def handle_client_request(client_socket):
    # Receive data from the client
    # incr = 1;
    # while True:
    #     incr = incr + 1
    #     print("haha",incr)
    #     print(client_socket)
    detectedClose = False
    username = None
    session_id = None
    request_data = process_request_data(client_socket)
    if not request_data:
        return "Bye"
    authenticated = None
    print(request_data)
    if extractHeader(request_data)['Connection'].lower() == 'close':
        detectedClose = True
    try:
        print('cookie', extractHeader(request_data)['Cookie'])
        if extractHeader(request_data)['Cookie']:
            username = get_key_from_value(
                session_storage, extractHeader(request_data)['Cookie'])
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
        if url == "/public_key":
            # Convert the server's public key to bytes
            server_public_key_bytes = publicKey.save_pkcs1(
                format='PEM')

            # Send the server's public key as a response
            headers = {
                "Content-Length": str(len(server_public_key_bytes)),
                "Content-Type": "application/octet-stream",
                "Connection": "keep-alive",
            }
            response_status_line = "HTTP/1.1 200 OK\r\n"
            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"
            response_header += "\r\n"

            # Send the response status line, headers, and public key
            client_socket.sendall(
                (response_status_line + response_header).encode('utf-8'))
            client_socket.sendall(server_public_key_bytes)
            return
        path = current_directory + url
        req_type = UrlParser.process_url(url)
        formatted_url = url.lstrip('/').replace('/', os.path.sep)
        vd_class = ViewDownload(client_socket, current_directory)
        if req_type == 'download':
            # Send the HTML content as the response

            vd_class.download_func(formatted_url)

        elif req_type == 'chunktrans':

            # convert it to OS format
            url_without_param = UrlParser.parse_qs(url)['path'].lstrip('/').replace('/', os.path.sep)
            file_path = os.path.join(current_directory, "data", url_without_param)

            # Check if the file exists
            if os.path.exists(file_path):
                # Open and read the file content
                vd_class.chunked_trans_func(file_path)

            else:
                send_404(client_socket)
        elif req_type == "return_list":
            vd_class.return_list_func(url)

        elif req_type == "view":

            vd_class.view_file_list(url)

        elif req_type == "home_page":
            vd_class.login_func()

        elif req_type == "unknown":
            send_400(client_socket)
        else:
            send_400(client_socket)

    if method == "HEAD":

        path = current_directory + url

        # Process as required for HEAD request

        if os.path.exists(path):  # Check if the requested resource exists

            # File exists, construct the headers

            headers = {
                # Assuming file size is the content length for HEAD
                "Content-Length": str(os.path.getsize(path)),
                "Content-Type": "application/octet-stream",  # Modify as per your file type
                "Connection": "keep-alive",
                "Set-Cookie": f"session_id={session_id}; HttpOnly; Path=/",
            }

            response_status_line = "HTTP/1.1 206 OK\r\n"

            response_header = ""

            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"

            response_header += "\r\n"

            # Send the response status line and headers (without body)

            client_socket.sendall(
                (response_status_line + response_header).encode('utf-8'))

        else:
            # File doesn't exist, handle accordingly with a 404 Not Found response
            error_response = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found"
            client_socket.sendall(error_response.encode('utf-8'))

    elif method == "POST":
        # Handle POST request - receive data from the client

        try:
            if url == "/receive_key":
                # Receive encrypted symmetric key from client
                session_id = extractHeader(request_data)['Session-ID']
                json_start = request_data.find('{')
                json_data = request_data[json_start:]

                # Extract the encrypted key from the JSON payload
                encrypted_symmetric_key_base64 = json.loads(json_data).get(
                    'encrypted_key', '')  # Convert bytes to string

                # Get the encrypted symmetric key from the JSON payload

                # Convert the Base64 string to bytes for decryption
                encrypted_symmetric_key = base64.b64decode(
                    encrypted_symmetric_key_base64)

                # Decrypt the symmetric key using the server's private key
                decrypted_symmetric_key = rsa.decrypt(
                    encrypted_symmetric_key, privateKey)

                # Now you have the decrypted symmetric key as bytes
                # You can use it for further symmetric encryption/decryption
                response_data = decrypted_symmetric_key
                session_keys[session_id] = decrypted_symmetric_key
                # Add necessary HTTP response headers
                response_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + \
                                   str(len(response_data)) + "\r\n\r\n"

                # Combine headers and response data
                response = response_headers.encode('utf-8') + response_data

                # Send the response to the client
                client_socket.sendall(response)
                return
            if url == "/testing":
                json_start = request_data.find('{')
                json_data = request_data[json_start:]

                # Extract the encrypted key from the JSON payload

                decrypted_symmetric_key_client = session_keys[extractHeader(request_data)[
                    'Session-ID']]

                encrypted_data_client = json.loads(json_data).get(
                    'encrypted_data', '')
                IV = extractHeader(request_data)[
                    'IV']
                decrypted_message = symmetric_decrypt(bytes.fromhex(encrypted_data_client),
                                                      decrypted_symmetric_key_client, bytes.fromhex(IV))
                response_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + \
                                   str(len(decrypted_message)) + "\r\n\r\n"

                # Combine headers and response data
                response = response_headers.encode('utf-8') + decrypted_message

                # Send the response to the client
                client_socket.sendall(response)
                return
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
                "Set-Cookie": f"session_id={session_id}; HttpOnly; Path=/",
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
                delete(client_socket=client_socket, url=url,
                       received_data=received_data, username=username)

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
        error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly POST method is allowed for file upload"
        client_socket.sendall(error_response.encode('utf-8'))
        # print(extractHeader(request_data))
        # if 'Connection' in extractHeader(request_data):
        #
        #     connection_header = headers['Connection'].lower()
        #     if connection_header == 'close':
        #         print("close")

    if detectedClose:
        return "Bye"


def process_path(raw_path):
    # Unquote the path to handle percent-encoded characters
    unquoted_path = unquote(raw_path)

    # Remove leading and trailing slashes
    processed_path = unquoted_path.strip('/')

    return processed_path


def upload(client_socket, url, received_data, username, headers):
    # Extract query parameters using parse_qs
    query_params = parse_qs(urlparse(url).query)

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
            filename_param = next(
                (param for param in params if param.lower().startswith("filename")), None)

            if filename_param:
                _, filename = filename_param.split("=")
                filename = filename.strip("\"")
                filename = filename.strip("\'")
                file_path = os.path.join(target_directory, filename)

                # Find the start and end of the file content
                file_content_start = received_data.find(b'\r\n\r\n') + 4
                file_content_end = received_data.find(b'--', file_content_start)

                if file_content_end != -1:
                    file_content = received_data[file_content_start:file_content_end - 2]
                else:
                    file_content = received_data[file_content_start:]

                with open(file_path, 'wb') as file:
                        file.write(file_content)

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
