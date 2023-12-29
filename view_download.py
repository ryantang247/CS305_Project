import os


class ViewDownload:

    def __init__(self, client_socket, current_directory):
        self.client_socket = client_socket
        self.current_directory = current_directory

    def view_file_list(self, url):
        url_parts = url.split('/')

        # Get the second part of the URL
        second_part = url_parts[1]
        path = os.path.join(self.current_directory, "data", second_part)
        files = self.get_file_list(path)

        # Render the HTML template with the file data
        html_content = self.generate_html(files)
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
        self.client_socket.sendall((response_status_line + response_header).encode('utf-8'))
        self.client_socket.sendall(html_content.encode('utf-8'))

    def get_file_list(self, directory_path):
        try:
            # Get the list of files and directories in the specified path
            entries = os.listdir(directory_path)

            return [
                entry
                for entry in entries
                if os.path.isfile(os.path.join(directory_path, entry))
            ]
        except OSError as e:
            # Handle any potential errors, such as permission issues or non-existent directories
            print(f"Error while getting file list: {e}")
            return []

    def generate_html(self, file_list):
        html_content = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n"
        html_content += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
        html_content += "<title>File List</title>\n</head>\n<body>\n"
        html_content += "<h1>File List</h1>\n<ul>\n"

        for file_name in file_list:
            html_content += f"    <li> <a href='{file_name}'>{file_name}></a></li>\n"

        html_content += "</ul>\n</body>\n</html>"

        return html_content

    def chunked_trans_func(self, file_path):
        with open(file_path, 'rb') as file:
            content = file.read()

            # Send the response headers
            headers = {
                "HTTP/1.1": "200 OK",
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/octet-stream",
                "Connection": "keep-alive",
            }
            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"

            # Append an empty line to indicate the end of headers
            response_header += "\r\n"
            self.client_socket.sendall(response_header.encode('utf-8'))

            chunk_size = 1024
            for i in range(0, len(content), chunk_size):
                chunk_size = min(1024, len(content) - i)
                chunk = f"{chunk_size}:X\r\n{content[i:i + chunk_size]}\r\n"
                self.client_socket.sendall(chunk.encode('utf-8'))

            closing_header = "0\r\n\r\n"
            self.client_socket.sendall(closing_header.encode('utf-8'))

    def return_list_func(self, url):
        url_parts = url.split('/')
        # Get the second part of the URL
        second_part = url_parts[1]
        path = os.path.join(self.current_directory, "data", second_part)
        files = self.get_file_list(path)
        headers = {
            "Content-Length": len(str(files)),
            "Content-Type": "text/html",
            "Connection": "keep-alive"
        }
        response_status_line = "HTTP/1.1 200 OK\r\n"
        response_header = ""
        for header, value in headers.items():
            response_header += f"{header}: {value}\r\n"
        response_header += "\r\n"

        # Send the response status line, headers, and HTML content
        self.client_socket.sendall((response_status_line + response_header).encode('utf-8'))
        self.client_socket.sendall(str(files).encode('utf-8'))

    def download_func(self, formatted_url):
        file_path = os.path.join(self.current_directory, "data", formatted_url)

        # Open the file in binary mode
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_content = file.read()
                content_length = len(file_content)

                import codecs
                hex_data = codecs.encode(file_content, "hex_codec")
                # content_type, _ = mimetypes.guess_type(file_path)
                # if not content_type:
                #     content_type = "application/octet-stream"  # Adjust content type based on the file

                # Construct headers
                headers = {
                    "Content-Length": len(hex_data),
                    "Content-Type": "application/octet-stream",
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
                self.client_socket.sendall((response_status_line + response_header).encode('utf-8'))

                # Send the file content
                self.client_socket.sendall(hex_data)
        else:
            # If the file is not found, send a 404 response
            self.send_404(self.client_socket)

    def login_func(self):
        path = os.path.join(self.current_directory, "login.html")
        with open(path, 'rb') as file:
            file_content = file.read()
            headers = {
                "HTTP/1.1": "200 OK",
                "Content-Length": str(len(file_content)),
                "Content-Type": "text/html",  # Set the appropriate content type for HTML
                "Connection": "open",
            }

            response_header = ""
            for header, value in headers.items():
                response_header += f"{header}: {value}\r\n"

                # Append an empty line to indicate the end of headers
            response_header += "\r\n"

            # Send the response header
            self.client_socket.sendall(response_header.encode('utf-8'))

            # Send the entire file content
            self.client_socket.sendall(file_content)

    def send_404(self):
        response = "HTTP/1.1 404 Not found\r\n"
        response += "Content-Type: text/html\r\n"
        response += "\r\n"
        response += "<html><head><title>404 Not found</title></head><body><h1>404 Not found</h1><p>File not found</p></body></html>"

        self.client_socket.sendall(response.encode('utf-8'))
        self.client_socket.close()
