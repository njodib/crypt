import requests
from Utils.Cipher import count_repeat_blocks

if __name__ == "__main__":
    # Get ciphertext
    URL = "https://www.cryptopals.com/static/challenge-data/8.txt"
    lines = requests.get(URL).text.splitlines()

    # Look for repeat blocks in each line
    for i, line in enumerate(lines, 1):
        if count_repeat_blocks(bytes.fromhex(line.strip()), 16) > 0:
            print("Ciphertext at line", i, "is ECB encrypted.")