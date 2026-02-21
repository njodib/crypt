from Utils.Oracles import C11_Oracle
from Utils.Cipher import detect_mode

if __name__ == '__main__':
    # Test: generate oracle, ensure the mode is properly detected each time.
    for _ in range(67):
        oracle = C11_Oracle()
        assert oracle.get_mode() == detect_mode(oracle)