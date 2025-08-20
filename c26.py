from c16 import Oracle
from Utils.BytesLogic import xor

profile = Oracle()
ctxt = profile.encrypt("hello9admin9true")
block2 = ctxt[16:32]
bit_flipper = b'\x00'*5+b'\x02'+b'\x00'*5+b'\x04'+b'\x00'*4
flipped_block2 = xor(block2, bit_flipper)
ctxt_flipped = ctxt[:16] + flipped_block2 + ctxt[32:]

assert profile.decrypt_and_check_admin(ctxt_flipped)
print("SUCCESS")
