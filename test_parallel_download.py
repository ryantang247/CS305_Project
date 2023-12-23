import requests
from concurrent.futures import ThreadPoolExecutor

def download_file(url, headers):
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(f"Downloaded {url}")
    else:
        print(f"Failed to download {url}")

def test_parallel_downloads():
    base_url = "http://localhost:8080/client1/goblok"  # Replace with your server URL

    # Simulate 10 parallel downloads
    urls = [f"{base_url}" for i in range(1, 20)]

    # Add your authorization header here
    authorization_header = {"Authorization": "Basic Y2xpZW50MToxMjM="}  # Replace with your actual access token

    with ThreadPoolExecutor(max_workers=10) as executor:
        # Pass the authorization header to the download_file function
        executor.map(lambda url: download_file(url, authorization_header), urls)

if __name__ == "__main__":
    test_parallel_downloads()
