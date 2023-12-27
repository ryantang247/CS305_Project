import requests
import time


def download_large_file(url, auth_token):
    headers = {"Authorization": f"Basic {auth_token}"}

    start_time = time.time()
    response = requests.get(url, headers=headers)
    end_time = time.time()

    if response.status_code == 200:
        print(f"Downloaded large file in {end_time - start_time} seconds")
    else:
        print(f"Failed to download large file")


if __name__ == "__main__":
    file_url = "http://localhost:8080/client1/large_video"
    authorization_token = "Y2xpZW50MToxMjM="  # Replace with the actual authorization token
    download_large_file(file_url, authorization_token)
