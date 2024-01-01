import os
class UrlParser:
    def __init__(self, url, current_directory):
        self.url = url
        self.current_directory = current_directory

    def process_url(self):
        # Extract the path and query parameters
        global operation_type
        parsed_url = UrlParser.parse_qs(self.url)

        path = parsed_url['path']
        path = path.strip("/")
        file_path = os.path.join(self.current_directory, "data", path)
        file_path = file_path.replace('/', os.path.sep)
        # Check for the existence of certain keywords in the path or query parameters

        if path.startswith("delete"):
            # This is an upload/delete type URL
            operation_type = "delete"
            # Example: Extract the file_path from the query parameters
            file_path = parsed_url.get("path", [None])[0]
        elif path.startswith("upload"):
            operation_type = "upload"
        elif path.startswith("persistenttest"):
            operation_type = "persistenttest"
        elif parsed_url['query'] == "SUSTech-HTTP=0":
            # This is a view type URL
            file_path = os.path.join(self.current_directory, "data", path)
            file_path = file_path.replace('/', os.path.sep)

            if os.path.isdir(file_path):
                operation_type = "view"
            else:
                operation_type = "not_found"

        elif parsed_url['query'] == "SUSTech-HTTP=1":
            # This is a view type URL
            file_path = os.path.join(self.current_directory, "data", path)
            file_path = file_path.replace('/', os.path.sep)

            if os.path.isdir(file_path):
                operation_type = "return_list"
            else:
                operation_type = "not_found"
        elif self.has_file_name():

            # if there is a file name, and there is no query
            if not parsed_url['query']:
                # Check if the path corresponds to an actual file
                file_path = os.path.join(self.current_directory, "data",path)
                file_path = file_path.replace('/',os.path.sep)
                if os.path.isfile(file_path):
                    # This is a valid download type URL with an actual file
                    operation_type = "download"
                elif os.path.isdir(file_path):
                    operation_type = "view"
                else:
                    # This is a directory, handle accordingly
                    operation_type = "not_found"
            elif parsed_url['query'] == 'chunked=1':
                file_path = os.path.join(self.current_directory, "data", path)
                file_path = file_path.replace(os.path.sep, '/')
                if os.path.isfile(file_path):
                    operation_type = "chunktrans"
                else:
                    operation_type = "unknown"
            else:
                operation_type = "unknown"
        
        elif path == "":
            operation_type = "home_page"
        else:
            # Unknown or unsupported URL type
            operation_type = "unknown"

        return operation_type

    def has_file_name(self):
        # Parse the URL manually or use a URL parsing library
        # For simplicity, let's assume the URL follows the format "http://example.com/path/to/filename.ext"
        path_segments = self.url.split('/')

        # Iterate through path segments
        for segment in path_segments:
            # Check if the segment looks like a file name
            if bool(os.path.splitext(segment)[0]):
                return True

        return False

    @staticmethod
    def extract_name_from_url(url):
        # Parse the URL
        path = url.split('/', 3)[-1].split('/', 1)[0]

        # Check if there is at least 1 segment
        if path:
            return path
        else:
            # Return None or raise an exception based on your specific requirement
            return None

    @staticmethod
    def extract_file_from_url(url):
        # Parse the URL
        path = url.split('/', 3)[-1].split('/', 1)[-1]

        # Check if there is at least 1 segment
        if path:
            return path
        else:
            # Return None or raise an exception based on your specific requirement
            return None

    @staticmethod
    def parse_qs(url):
        # Initialize variables to store different components of the URL
        scheme = ""
        host = ""
        path = ""
        query = ""
        fragment = ""

        # Split the URL into scheme, netloc, path, query, and fragment
        scheme_idx = url.find("://")
        if scheme_idx != -1:
            scheme = url[:scheme_idx]
            url = url[scheme_idx + 3:]

        # Find the index of the fragment identifier (#)
        fragment_idx = url.find("#")
        if fragment_idx != -1:
            fragment = url[fragment_idx + 1:]
            url = url[:fragment_idx]

        # Find the index of the query parameters (?)
        query_idx = url.find("?")
        if query_idx != -1:
            query = url[query_idx + 1:]
            url = url[:query_idx]

        # Split the remaining URL into host and path
        path_idx = url.find("/")
        if path_idx != -1:
            host = url[:path_idx]
            path = url[path_idx:]
        else:
            host = url

        # Return the parsed components as a dictionary
        parsed_url = {
            "scheme": scheme,
            "host": host,
            "path": path,
            "query": query,
            "fragment": fragment
        }

        return parsed_url
