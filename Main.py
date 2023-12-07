import os
import signal
import selectors
import threading
import time
from http_messages import HttpRequest, HttpResponse, HttpStatusCode, HttpMethods
from http_server import HttpServer
from Uri import Uri

url = "http://localhost:8080/upload?path=/11912113/"


# Extract query parameters
query_params = {}
if "?" in url:
    path_param = url.split("?")[1]
    path_param = path_param.split("&")
    for param in path_param:
        key, value = param.split("=")
        query_params[key] = value


print(query_params)