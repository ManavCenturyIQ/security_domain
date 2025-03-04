from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import base64

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument(
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Safari/537.36"
)  # Custom User-Agent

# Set up the WebDriver
driver = webdriver.Chrome(options=chrome_options)

try:
    # Open the webpage
    driver.get("https://www.century.ae")  # Replace with your URL

    # Set custom headers (if needed for additional requests)
    driver.execute_cdp_cmd(
        "Network.setUserAgentOverride",
        {
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Safari/537.36"
        },
    )

    # Use Chrome DevTools Protocol for full-page screenshot
    screenshot = driver.execute_cdp_cmd("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})

    # Decode the Base64-encoded string and save it as an image
    with open("full_screenshot.png", "wb") as file:
        file.write(base64.b64decode(screenshot["data"]))

    print("Full-page screenshot saved as full_screenshot.png")
finally:
    driver.quit()
