import requests

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "qwen3.6:latest",
        "prompt": "You are a financial analyst. Nifty is at 24100. Should I deploy 50000 in ETFs?",
        "stream": False
    }
)

print(response.json()["response"])