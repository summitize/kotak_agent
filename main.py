import json
import logging
from kotak_neo_client import KotakNeoClient

# Get logger configured in client
logger = logging.getLogger("KotakNeoClient")

def main():
    logger.info("=========================================")
    logger.info("Kotak Neo Holdings Fetcher starting...")
    logger.info("=========================================")
    
    # Instantiate client, this automatically loads environment variables from .env
    # and validates configuration.
    try:
        client = KotakNeoClient()
    except Exception as e:
        logger.error(f"Failed to initialize client: {e}")
        return
        
    try:
        # Fetch holdings (this will trigger login first if session details are absent)
        response = client.get_holdings()
        
        # Print raw response to console
        print("\n--- RAW HOLDINGS API RESPONSE ---")
        print(response.text)
        print("---------------------------------\n")
        
        # Save response to holdings.json if status is 200
        if response.status_code == 200:
            try:
                holdings_data = response.json()
                with open("holdings.json", "w", encoding="utf-8") as f:
                    json.dump(holdings_data, f, indent=4, ensure_ascii=False)
                logger.info("Successfully saved holdings response to holdings.json")
            except Exception as e:
                logger.error(f"Failed to parse JSON and save to holdings.json: {e}")
                # Save raw text as fallback
                with open("holdings.json", "w", encoding="utf-8") as f:
                    f.write(response.text)
                logger.info("Saved raw response text to holdings.json as fallback")
        else:
            logger.warning(f"Holdings API did not return success status. HTTP {response.status_code}. Response was not structured saved.")
            
    except Exception as e:
        logger.error(f"An unexpected error occurred during execution: {e}")

if __name__ == "__main__":
    main()
