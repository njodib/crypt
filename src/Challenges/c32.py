import requests
import time
import numpy as np

URL = "http://localhost:9000/test"
FILE = "foo"
HEX_CHARS = "0123456789abcdef"
MAX_SAMPLES = 20  # Max samples to take if it's "close"
THRESHOLD = 0.004 # 4ms - slightly less than our 5ms artificial delay

def get_sample(signature):
    start = time.perf_counter()
    requests.get(URL, params={"file": FILE, "signature": signature})
    return time.perf_counter() - start

def crack_signature():
    known_sig = ""
    
    for i in range(40):
        results = {char: [] for char in HEX_CHARS}
        
        # We do rounds of sampling to find the winner faster
        for round in range(MAX_SAMPLES):
            for char in HEX_CHARS:
                test_sig = known_sig + char + ("0" * (39 - len(known_sig)))
                results[char].append(get_sample(test_sig))
            
            # Calculate medians for this round
            medians = {c: np.median(times) for c, times in results.items()}
            sorted_chars = sorted(medians.items(), key=lambda x: x[1], reverse=True)
            
            best_char, best_time = sorted_chars[0]
            second_best_char, second_best_time = sorted_chars[1]
            
            # If the best is significantly slower than the second best, 
            # we've likely found our byte and can exit the round early.
            if (best_time - second_best_time) > THRESHOLD and round > 2:
                print(f"Confidence high after {round+1} samples.")
                break
        
        known_sig += best_char
        print(f"Pos {i+1}: {known_sig} (Delta: {best_time - second_best_time:.4f}s)")

    print(f"\nFinal HMAC: {known_sig}")

if __name__ == "__main__":
    crack_signature()