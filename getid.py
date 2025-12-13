import requests
import time
import sys

# Your NEW Token
TOKEN = "8306274058:AAH0wLqna6yhiT2KTt3PZOWCvxbNaa8AtOg"
URL = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

def get_chat_id():
    print("[-] Contacting Telegram API...")
    try:
        response = requests.get(URL)
        data = response.json()
        
        if not data['ok']:
            print(f"[!] API Error: {data.get('description')}")
            return

        results = data['result']
        
        if not results:
            print("\n" + "!"*50)
            print("[ERROR] No messages found!")
            print("1. Go to your bot in Telegram.")
            print("2. Type 'Hello' or click /start.")
            print("3. Run this script again.")
            print("!"*50)
            return

        # Get the chat ID from the most recent message
        chat_id = results[-1]['message']['chat']['id']
        sender = results[-1]['message']['from'].get('first_name', 'User')
        
        print("\n" + "="*40)
        print(f"SUCCESS! Found message from: {sender}")
        print(f"YOUR CHAT ID IS: {chat_id}")
        print("="*40)
        print(f"\nCopy this ID into config.py.")
        
    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    get_chat_id()