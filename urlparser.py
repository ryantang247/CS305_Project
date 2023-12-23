class UrlParser:
    @staticmethod
    def process_url(url):
        # Extract the path and query parameters
        global operation_type
        parsed_url = UrlParser.parse_qs(url)
        path = parsed_url['path']

        # Check for the existence of certain keywords in the path or query parameters
        if path.startswith("delete"):
            # This is an upload/delete type URL
            operation_type = "delete"
            # Example: Extract the file_path from the query parameters
            file_path = parsed_url.get("path", [None])[0]
        elif path.startswith("upload"):
            operation_type = "upload"
        elif parsed_url['query'] == "SUSTech-HTTP=0":
            # This is a view type URL
            operation_type = "home_page"
        elif parsed_url['query'] == "SUSTech-HTTP=1":
            # This is a view type URL
            operation_type = "view"
        elif len(path.split("/")) >= 3:

            if not parsed_url['query']:
                # This is a valid download type URL with both {name} and {file_name} segments (Maybe subject to change)
                operation_type = "download"
            if parsed_url['query'] == 'chunked=1':
                operation_type = "chunktrans"
        else:
            # Unknown or unsupported URL type
            operation_type = "unknown"

        return operation_type

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
