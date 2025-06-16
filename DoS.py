import requests
import threading

bridge_ip = "192.168.0.13"
port_number = "8080"
bridge_token = "123658" # Random token

url = f"http://{bridge_ip}:{port_number}/info?token={bridge_token}"

def send_request():
    while True:
        try:
            # Sending the HTTP GET request
            response = requests.get(url, timeout=5)
            if response.status_code == 200: # Successful request
                print("Request sent successfully")
            elif response.status_code == 503: # Service unavailable
                print("Service unavailable (503)")
            else: # Other failed connections
                print(f"Failed to send request: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
        
def main():
    for _ in range(10):  # Number of threads to create
        thread = threading.Thread(target=send_request)
        thread.start()
        
if __name__ == "__main__":
    main()