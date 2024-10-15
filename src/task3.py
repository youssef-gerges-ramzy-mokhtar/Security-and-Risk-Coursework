from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

def generate_keys():
  priv_key = ec.generate_private_key(ec.SECP384R1())
  return priv_key, priv_key.public_key()

def sha256_hash(text):
  hasher = hashes.Hash(hashes.SHA256())
  hasher.update(text.encode('utf-8'))
  return hasher.finalize()

def sign(priv_key, hash_digest):
  return priv_key.sign(
      hash_digest,
      ec.ECDSA(utils.Prehashed(hashes.SHA256()))
  )

def verify_signature(signature, text, pub_key):
  try:
    pub_key.verify(
        signature,
        text.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )

    return True
  except:
    return False

if __name__ == "__main__":
  # Generating Keys
  priv_key, pub_key = generate_keys()
  print("private key: ", priv_key.private_numbers().private_value)
  print("public key (x, y): ", pub_key.public_numbers().x, pub_key.public_numbers().y)
  print()

  # Hashing Plain Text
  plain_text = "LZSCC.363"
  hash_value = sha256_hash(plain_text)
  print("SHA-256 hash of '{}': {}".format(plain_text, hash_value.hex()))
  print()

  # Creating the digital signature
  signature = sign(priv_key, hash_value)
  print(signature)
  print()

  # Verifying the digital signature
  verified = verify_signature(signature, plain_text, pub_key)
  print("Verified: ", verified)