from Utils.BytesLogic import best_single_xor_key, score, xor
import requests

if __name__ == "__main__":
    max_score = -float('inf')
    message = None
    URL = "https://www.cryptopals.com/static/challenge-data/4.txt"
    for line in requests.get(URL).text.splitlines():
        l = bytes.fromhex(line)
        key = best_single_xor_key(l)
        candidate = xor(l, key)
        candidate_score = score(candidate)
        if candidate_score > max_score:
            max_score = candidate_score
            message = candidate
    print(message.decode('utf-8'))