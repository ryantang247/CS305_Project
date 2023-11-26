import os
import signal
import selectors
import threading
import time
from http_messages import HttpRequest, HttpResponse, HttpStatusCode, HttpMethods
from http_server import HttpServer
from Uri import Uri


def ensure_enough_resource(resource, soft_limit, hard_limit):
    old_limit = os.getrlimit(resource)

    print(f"Old limit: {old_limit.rlim_cur} (soft limit), {old_limit.rlim_max} (hard limit).")
    print(f"New limit: {soft_limit} (soft limit), {hard_limit} (hard limit).")

    try:
        os.setrlimit(resource, (soft_limit, hard_limit))
    except Exception as e:
        print(f"Warning: Could not update resource limit ({str(e)}).")
        print("Consider setting the limit manually with ulimit")
        exit(-1)


def say_hello(request):
    response = HttpResponse(HttpStatusCode.Ok)
    response.set_header("Content-Type", "text/plain")
    response.set_content("Hello, world\n")
    return response


def send_html(request):
    response = HttpResponse(HttpStatusCode.Ok)
    content = "<!doctype html>\n"
    content += "<html>\n<body>\n\n"
    content += "<h1>Hello, world in an Html page</h1>\n"
    content += "<p>A Paragraph</p>\n\n"
    content += "</body>\n</html>\n"

    response.set_header("Content-Type", "text/html")
    response.set_content(content)
    return response


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8080
    server = HttpServer(host, port)

    # Register a few endpoints for demo and benchmarking
    server.register_http_request_handler("/", HttpMethods.HEAD, say_hello)
    server.register_http_request_handler("/", HttpMethods.GET, say_hello)
    server.register_http_request_handler("/hello.html", HttpMethods.HEAD, send_html)
    server.register_http_request_handler("/hello.html", HttpMethods.GET, send_html)

    try:
        # Uncomment the following lines if you want to set resource limits
        # print("Setting new limits for file descriptor count..")
        # ensure_enough_resource(signal.RLIMIT_NOFILE, 15000, 15000)

        # print("Setting new limits for number of threads..")
        # ensure_enough_resource(signal.RLIMIT_NPROC, 60000, 60000)

        print("Starting the web server..")
        server.start()
        print(f"Server listening on {host}:{port}")

        print("Enter [quit] to stop the server")
        while True:
            command = input()
            if command == "quit":
                break
            time.sleep(0.1)

        print("'quit' command entered. Stopping the web server..")
        server.stop()
        print("Server stopped")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        exit(-1)
