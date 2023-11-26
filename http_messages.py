from enum import Enum
from typing import Dict
from Uri import Uri


class HttpMethods(Enum):
    GET = 1
    HEAD = 2
    POST = 3


class HttpVersions(Enum):
    HTTP_1_0 = 'HTTP/1.0'
    HTTP_1_1 = 'HTTP/1.1'
    HTTP_2_0 = 'HTTP/2.0'


class HttpStatusCode(Enum):
    # 2xx: Success
    OK = 200
    PartialContent = 206

    # 3xx: Redirection
    Redirect = 301

    # 4xx: Client Error
    BadRequest = 400
    Unauthorized = 401
    Forbidden = 403
    NotFound = 404
    MethodNotAllowed = 405
    RangeNotSatisfiable = 416

    # 5xx: Server Error
    BadGateway = 502
    ServiceTemporarilyUnavailable = 503


class HttpMessageInterface:

    def __init__(self):
        self.version = HttpVersions.HTTP_1_1
        self.headers = {}
        self.content = ""

    def set_header(self, key, value):
        self.headers[key] = value

    def remove_header(self, key):
        if key in self.headers:
            del self.headers[key]

    def clear_header(self):
        self.headers = {}

    def set_content(self, content):
        self.content = content
        self.set_content_length()

    def clear_content(self):
        self.content = ""
        self.set_content_length()

    def set_content_length(self):
        self.set_header("Content-Length", str(len(self.content)))


class HttpRequest(HttpMessageInterface):
    def __init__(self):
        super().__init__()
        self.methods = HttpMethods.GET
        self.uri = Uri("")

    def set_method(self, method):
        self.methods = method

    def get_method(self):
        return self.methods

    def set_uri(self, uri):
        self.uri = uri

    def get_uri(self):
        return self.uri


class HttpResponse(HttpMessageInterface):
    def __init__(self, status_code=None):
        super().__init__()
        self.status_code = status_code

    def set_status_code(self, status_code):
        self.status_code = status_code


def string_to_method(method_string):
    method_string_uppercase = method_string.upper()
    if method_string_uppercase == 'GET':
        return HttpMethods.GET
    elif method_string_uppercase == 'HEAD':
        return HttpMethods.HEAD
    elif method_string_uppercase == 'POST':
        return HttpMethods.POST

    else:
        raise ValueError("Unexpected HTTP method")


def string_to_version(version_string):
    version_string_uppercase = version_string.upper()

    if version_string_uppercase == "HTTP/1.0":
        return HttpVersions.HTTP_1_0
    elif version_string_uppercase == "HTTP/1.1":
        return HttpVersions.HTTP_1_1
    elif version_string_uppercase in ["HTTP/2", "HTTP/2.0"]:
        return HttpVersions.HTTP_2_0
    else:
        raise ValueError("Unexpected HTTP version")


def to_string(string):
    return str(string)


def to_string_request(request):
    result = f"{request.methods.name} / {request.uri.path} / {request.version.value}\r\n"
    for key, value in request.headers.items():
        result += f"{key}: {value}\r\n"
    result += "\r\n"
    result += request.content
    return result


def to_string_response(response, send_content=True):
    result = f"{response.version.value} {response.status_code.value} {response.status_code.name}\r\n"
    for key, value in response.headers.items():
        result += f"{key}: {value}\r\n"
    result += "\r\n"
    if send_content:
        result += response.content
    return result


def string_to_request(request_string):
    start_lines, header_lines, message_body = request_string.split("\r\n", 2)
    method, path, version = start_lines.split()
    Request = HttpRequest()
    Request.set_method(string_to_method(method))
    Request.set_uri(Uri(path))

    if string_to_version(version) != Request.version:
        raise ValueError("HTTP version not supported!")

    for line in header_lines.split("\r\n"):
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        Request.set_header(key, value)

    Request.set_content(message_body)
    return Request


def string_to_response(response_string):
    raise NotImplementedError("Method not implemented")


if __name__ == "__main__":
    # Example usage
    request = HttpRequest()
    request.set_method(HttpMethods.GET)
    request.set_uri(Uri("example"))
    request.set_header("Host", "localhost")
    request.set_content("This is the content of the request.")

    print(to_string_request(request))

    response = HttpResponse()
    response.set_status_code(HttpStatusCode.BadRequest)
    response.set_header("Server", "MyServer")
    response.set_content("This is the content of the response.")

    print(to_string_response(response))
