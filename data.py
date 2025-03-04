import requests
from bs4 import BeautifulSoup

# Your data to check (e.g., address, phone number)
MY_DATA = {
    "address": "Dubai 6th Floor, Building 4, Emaar Square, Downtown Dubai, P.O. Box 65777, Dubai, United Arab Emirates",
    "phone": "+971 (4) 356 2800"
}

# List of target websites to scan
WEBSITE_LIST = [
    "https://www.century.ae/en/"
]

def fetch_homepage(url):
    """
    Fetch the homepage content of a website with a browser-like User-Agent.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return None


def check_data_in_website(html_content, data):
    """
    Check if the specified data exists in the website's content.
    """
    # Use BeautifulSoup to parse HTML content
    soup = BeautifulSoup(html_content, "html.parser")
    text = soup.get_text()  # Extract all visible text from the HTML
    
    # Check if any of the data is present in the text
    for key, value in data.items():
        if value in text:
            return key, value
    return None, None

def main():
    """
    Main function to check a list of websites for your data.
    """
    print("Checking websites for my data...\n")
    
    for website in WEBSITE_LIST:
        print(f"Checking {website}...")
        html_content = fetch_homepage(website)
        
        if html_content:
            key, value = check_data_in_website(html_content, MY_DATA)
            if key:
                print(f"⚠️ Found '{key}' ('{value}') on {website}")
            else:
                print(f"✅ No data found on {website}")
        print("-" * 50)

if __name__ == "__main__":
    main()
