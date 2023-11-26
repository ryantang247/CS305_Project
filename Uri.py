class Uri:
    def __init__(self, path=""):
        self.path = path
        self.scheme = ""
        self.host = ""
        self.port = 0
        self.set_path_to_lowercase()

    def __lt__(self, other):
        return self.path < other.path

    def __eq__(self, other):
        return self.path == other.path

    def __hash__(self):
        return hash(self.path)

    def set_path(self, path):
        self.path = path
        self.set_path_to_lowercase()

    def set_path_to_lowercase(self):
        self.path = self.path.lower()
