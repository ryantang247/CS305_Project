import base64
import errno
import selectors
import socket
import threading
import time
import random
import select
import logging
from http_messages import HttpResponse, HttpStatusCode, string_to_request, to_string, HttpMethods
from Uri import Uri


class EventData:
    """
    Represents data associated with an event.
        fd: File descriptor (socket) associated with the event.
        length: Length of data.
        cursor: Position of the cursor in the data.
        buffer: Byte array to store incoming or outgoing data.
    """
    def __init__(self):
        self.fd = 0
        self.length = 0
        self.cursor = 0
        self.buffer = bytearray(4096)


class HttpServer:
    """
    Represents the HTTP server with methods to
    start and stop the server, handle requests, and manage connections.

    """
    K_MAX_BUFFER_SIZE = 4096   # Maximum buffer size for reading/writing data.
    K_BACKLOG_SIZE = 1000   # Maximum number of pending connections in the socket's listen queue.
    K_MAX_CONNECTIONS = 10000   # Maximum number of connections allowed.
    K_MAX_EVENTS = 10000  # Maximum number of events to retrieve during a call to select.
    K_THREAD_POOL_SIZE = 5   # K_THREAD_POOL_SIZE: Number of worker threads to handle events.

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock_fd = None
        self.running = False
        self.running_lock = threading.Lock()  # A lock to ensure thread safety when starting and stopping the server.
        self.worker_epoll_fd = []  #
        self.rng = random.Random(time.time())
        self.sleep_times = (10, 100)
        self.listener_thread = None
        self.worker_threads = []  #
        self.worker_events = [None] * self.K_THREAD_POOL_SIZE
        self.request_handlers = {}
        self.create_socket()
        self.persistent_connections = set()  # Set to keep track of persistent connections

    def start(self):
        """
        Starts the HTTP server.

        Binds the socket, starts the listener thread, and initializes worker threads to handle events.
        """
        with self.running_lock:
            if self.running:
                raise RuntimeError("Server is already running.")
            self.running = True

        opt = 1
        server_address = (self.host, self.port)

        if self.sock_fd is None:
            raise RuntimeError("Failed to create a TCP Socket")

        self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, opt)
        self.sock_fd.bind(server_address)
        self.sock_fd.listen(self.K_BACKLOG_SIZE)

        self.set_up_epoll()
        self.listener_thread = threading.Thread(target=self.listen)
        self.listener_thread.start()

        # Ensure self.worker_threads is initialized as an empty list
        self.worker_threads = []

        for i in range(self.K_THREAD_POOL_SIZE):
            worker_thread = threading.Thread(target=self.process_events, args=(i,))
            self.worker_threads.append(worker_thread)
            print(f"Thread {i} created: {worker_thread}")
            worker_thread.start()

    def stop(self):
        """
        Stops the server, joining the listener and worker threads, and closes the socket.

        """
        with self.running_lock:
            if not self.running:
                raise RuntimeError("Server is not running.")
            self.running = False

        self.listener_thread.join()
        for i in range(self.K_THREAD_POOL_SIZE):
            self.worker_threads[i].join()

            # Close the selector explicitly
            self.worker_epoll_fd[i].close()

        self.sock_fd.close()

    def register_http_request_handler(self, path, method, callback):
        uri = Uri(path)
        if uri not in self.request_handlers:
            self.request_handlers[uri] = {}
        self.request_handlers[uri][method] = callback

    def create_socket(self):
        """
        Creates a TCP socket and sets it to non-blocking mode.

        """
        try:
            self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_fd.setblocking(False)  # Set the socket to non-blocking
        except AttributeError as e:
            raise RuntimeError(f"Error creating socket: {e}")

    def set_up_epoll(self):
        """
         Initializes a list of selectors.DefaultSelector objects for worker

        """
        for i in range(self.K_THREAD_POOL_SIZE):
            epoll_fd = selectors.DefaultSelector()
            self.worker_epoll_fd.append(epoll_fd)

    # For Persistent Connection
    def mark_connection_as_persistent(self, client_fd):
        self.persistent_connections.add(client_fd)

    def mark_connection_as_non_persistent(self, client_fd):
        self.persistent_connections.discard(client_fd)

    def listen(self):
        """
        Listens for incoming connections and handles them.

        Accepts a connection, sets it to non-blocking mode,
        and marks it as persistent or non-persistent based on the "Connection" header.

        Registers the connection with the appropriate worker thread for further handling.
        """
        while self.running:
            try:
                client_fd, client_address = self.sock_fd.accept()
                if client_fd.fileno() == -1:  # Check for invalid socket descriptor
                    continue

                client_fd.setblocking(0)

                # Check the Connection header
                try:
                    connection_header = client_fd.recv(self.K_MAX_BUFFER_SIZE).decode("utf-8")
                    if "Connection: Close" in connection_header:
                        self.mark_connection_as_non_persistent(client_fd)
                        logging.info(f"Connection marked as non-persistent: {client_fd}")
                    else:
                        self.mark_connection_as_persistent(client_fd)
                        logging.info(f"Connection marked as persistent: {client_fd}")

                    # Handle the connection as before
                    client_data = EventData()
                    client_data.fd = client_fd
                    self.control_epoll_event(
                        self.worker_epoll_fd[client_fd.fileno() % self.K_THREAD_POOL_SIZE],
                        selectors.EVENT_READ | selectors.EVENT_WRITE,
                        client_fd,
                        op=2,  # selectors.EVENT_MODIFY
                        data=client_data,
                    )
                except socket.error as e:
                    logging.error(f"Socket error during connection setup: {e}")
                    time.sleep(self.rng.uniform(*self.sleep_times))
            except socket.error as e:
                if e.errno == 10035:  # WSAEWOULDBLOCK
                    time.sleep(0.1)  # Retry after a short duration
                else:
                    logging.error(f"Socket error during accept: {e}")
                    time.sleep(self.rng.uniform(*self.sleep_times))

    def process_events(self, worker_id):
        """
        Each worker thread handles events using selectors.DefaultSelector.

        Retrieves and processes events (read/write) using the select method.

        Handles read and write events by calling corresponding methods.

        Checks for socket errors and closes connections if necessary.

        """
        epoll_fd = self.worker_epoll_fd[worker_id]

        while self.running:
            try:
                events = epoll_fd.select(timeout=0)
                for key, mask in events:
                    client_fd = key.fileobj
                    data = key.data

                    if mask & selectors.EVENT_READ:
                        self.handle_read_event(epoll_fd, data, client_fd)
                    if mask & selectors.EVENT_WRITE:
                        self.handle_write_event(epoll_fd, data, client_fd)
            except select.error as e:
                if e.errno == errno.EBADF:
                    logging.error(f"Invalid file descriptor in worker {worker_id}")
                    break  # Exit the loop or handle appropriately
                else:
                    logging.error(f"Select error in worker {worker_id}: {e}")
                continue
            except AttributeError:
                # Handle the AttributeError if 'closed' attribute is not present
                logging.info(f"Selector in worker {worker_id} does not have 'closed' attribute")
                break  # Exit the loop or handle appropriately


    def handle_epoll_event(self, epoll_fd, data, fd, events):
        if events & selectors.EVENT_READ:
            self.handle_read_event(epoll_fd, data, fd)
        if events & selectors.EVENT_WRITE:
            self.handle_write_event(epoll_fd, data, fd)

    def handle_read_event(self, epoll_fd, data, fd):
        try:
            byte_count = fd.recv_into(data.buffer, self.K_MAX_BUFFER_SIZE)
            if byte_count > 0:
                response = EventData()
                response.fd = fd
                self.handle_http_data(data, response)
                self.control_epoll_event(epoll_fd, selectors.EVENT_WRITE, fd, data=response)

                # Check if the connection is marked as non-persistent
                if fd not in self.persistent_connections:
                    self.control_epoll_event(epoll_fd, selectors.EVENT_READ | selectors.EVENT_WRITE, fd,
                                             op=1)  # selectors.EVENT_DELETE
                    fd.close()
            else:
                if byte_count == self.K_MAX_BUFFER_SIZE:  # retry
                    self.control_epoll_event(epoll_fd, selectors.EVENT_READ, fd, data=data)
                else:  # other error
                    self.control_epoll_event(epoll_fd, selectors.EVENT_READ | selectors.EVENT_WRITE, fd,
                                             op=1)  # selectors.EVENT_DELETE
                    fd.close()
        except socket.error as e:
            if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):  # retry
                self.control_epoll_event(epoll_fd, selectors.EVENT_READ, fd, data=data)
            else:  # other error
                self.control_epoll_event(epoll_fd, selectors.EVENT_READ | selectors.EVENT_WRITE, fd,
                                         op=1)  # selectors.EVENT_DELETE
                fd.close()
                logging.error(f"Socket error during read: {e}")

    def handle_write_event(self, epoll_fd, data, fd):
        response = data
        try:
            byte_count = fd.send(response.buffer[response.cursor: response.cursor + response.length])
            if byte_count >= 0:
                if byte_count < response.length:  # there are still bytes to write
                    response.cursor += byte_count
                    response.length -= byte_count
                    self.control_epoll_event(epoll_fd, selectors.EVENT_WRITE, fd, data=response)
                else:  # we have written the complete message
                    self.control_epoll_event(epoll_fd, selectors.EVENT_READ | selectors.EVENT_WRITE, fd,
                                             op=2)  # selectors.EVENT_MODIFY
        except socket.error as e:
            if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):  # retry
                self.control_epoll_event(epoll_fd, selectors.EVENT_WRITE, fd, data=response)
            else:  # other error
                self.control_epoll_event(epoll_fd, selectors.EVENT_READ | selectors.EVENT_WRITE, fd,
                                         op=1)  # selectors.EVENT_DELETE
                fd.close()
                logging.error(f"Socket error during write: {e}")

    def handle_http_data(self, raw_request, raw_response):
        request_string = raw_request.buffer.decode("utf-8")
        try:
            http_request = string_to_request(request_string)
            http_response = self.handle_http_request(http_request)
        except ValueError as e:
            http_response = HttpResponse(HttpStatusCode.BadRequest)
            http_response.set_content(str(e))
        except NotImplementedError as e:
            http_response = HttpResponse(HttpStatusCode.ServiceTemporarilyUnavailable)
            http_response.set_content(str(e))
        except Exception as e:
            http_response = HttpResponse(HttpStatusCode.ServiceTemporarilyUnavailable)
            http_response.set_content(str(e))

        # Set response to write to the client
        response_string = to_string(http_response)
        raw_response.buffer = response_string.encode("utf-8")
        raw_response.length = len(response_string)

    def handle_http_request(self, request):
        uri = request.uri

        # Check for authorization
        if not self.check_authorization(request.headers):
            return HttpResponse(HttpStatusCode.Unauthorized,)

        if uri not in self.request_handlers:
            return HttpResponse(HttpStatusCode.NotFound)

        if request.method not in self.request_handlers[uri]:
            return HttpResponse(HttpStatusCode.MethodNotAllowed)

        return self.request_handlers[uri][request.method](request)

    def check_authorization(self, headers):
        authorization_header = headers.get("Authorization")

        if not authorization_header or not authorization_header.startswith("Basic "):
            return False

        encoded_credentials = authorization_header.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = decoded_credentials.split(":")

        # Check username and password (replace with your own authentication logic)
        return self.validate_user(username, password)


    def validate_user(self, username, password):
        # Replace this with your actual user authentication logic
        valid_users = {"user1": "password1", "user2": "password2"}

        return valid_users.get(username) == password

    def control_epoll_event(self, epoll_fd, events, fd, op=selectors.EVENT_READ, data=None):
        """
        Registers, modifies, or unregisters events for a file descriptor in the selector.
        
        """
        key = epoll_fd.get_key(fd)
        if key:
            if op == selectors.EVENT_READ or op == selectors.EVENT_WRITE:
                epoll_fd.modify(fd, events, data=data)
            elif op == 2:  # selectors.EVENT_MODIFY
                epoll_fd.modify(fd, events, data=data)
            elif op == 1:  # selectors.EVENT_DELETE
                epoll_fd.unregister(fd)
        else:
            epoll_fd.register(fd, events, data=data)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Example usage
    server = HttpServer("127.0.0.1", 8080)


    def handle_request(request):
        response = HttpResponse(HttpStatusCode.OK)
        response.set_content("Hello, world!")
        return response


    server.register_http_request_handler("/", HttpMethods.GET, handle_request)

    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
