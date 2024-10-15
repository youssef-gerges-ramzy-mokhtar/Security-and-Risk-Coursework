from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_parameters, load_pem_public_key, load_pem_private_key

def encrypt(plain, key):
  cipher = []
  for character in plain:
    subsituted_chr = (ord(character) + key) % 128
    cipher.append(chr(subsituted_chr))

  return ''.join(cipher)

def decrypt(cipher, key):
  plain = []
  for character in cipher:
    subsituted_chr = (ord(character) - key) % 128
    plain.append(chr(subsituted_chr))

  return ''.join(plain)

class InternetUser:
  parameters = dh.generate_parameters(generator=2, key_size=2048)

  def __init__(self, ip):
    self.priv_key, self.pub_key = self.generate_keys()
    self.ip = ip # every internet user have an ip
    self.interceptor = None

  def generate_keys(self):
    priv_key = InternetUser.parameters.generate_private_key()
    return priv_key, priv_key.public_key()

  def sendKey(self, receiver):
    if self.interceptor == None:
      receiver.receivePubKey(self.getPubKeyPem(), self.ip)
    else:
      self.interceptor.interceptKey(self.ip, self.getPubKeyPem(), receiver)

  def receivePubKey(self, senderPubKeyPem, senderIp):
    print("Received Public Key from: ", senderIp)
    self.sender_pub_key = load_pem_public_key(senderPubKeyPem)
    my_pub_key, self.derived_key = self.Diffie_Hellman()

  def sendMessage(self, receiver, msg):
    if self.derived_key == None:
      raise Exception("No Key Exchange took place")

    cipher = encrypt(msg, int.from_bytes(self.derived_key, 'little'))

    if self.interceptor == None:
      receiver.receiveMessage(self.ip, cipher)
    else:
      self.interceptor.interceptMessage(self.ip, cipher, receiver)

  def receiveMessage(self, senderIp, cipher):
    msg = decrypt(cipher, int.from_bytes(self.derived_key, 'little'))
    print("Message Received: ", msg)
    print("\t - Received From: ", senderIp)

  def setInterceptor(self, interceptor):
    self.interceptor = interceptor

  def getPubKeyPem(self):
    return self.pub_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

  def Diffie_Hellman(self):
    shared_key = self.priv_key.exchange(self.sender_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    return (self.getPubKeyPem(), derived_key)

class Interceptor(InternetUser):
  def __init__(self, ip, evil):
    InternetUser.__init__(self, ip)
    self.derived_keys = {}
    self.evil = evil

  def addTargetedInternetUser(self, targetUser):
    targetUser.setInterceptor(self)

  # here the interceptor will use the senderPubKey to create an encryption key
  # and instead of sending the senderPubKey to the receiver he will send his own pubKey to the receiver
  def interceptKey(self, senderIp, senderPubKey, receiver):
    self.sender_pub_key = load_pem_public_key(senderPubKey)

    receiver.receivePubKey(self.getPubKeyPem(), senderIp) # the interceptor is sending his public key to the receiver and using the snederIp to make it seem legitimate (spoofing)
    pub_key, derived_key = self.Diffie_Hellman()

    self.derived_keys[senderIp] = derived_key

  def interceptMessage(self, senderIp, cipherMsg, receiver):
    sender_key = self.derived_keys[senderIp] # interceptor getting the encryption key associated with the sender
    receiver_key = self.derived_keys[receiver.ip] # interceptor getting the encryption key associate with the receiver

    plainMsg = decrypt(cipherMsg, int.from_bytes(sender_key, 'little')) # interceptor decrypting the cipher text of the sender
    print("Intercepted Message: ", plainMsg)

    if self.evil:
      self.modifyMsg(senderIp, plainMsg, receiver, receiver_key)
    else:
      self.eavesdropMsg(senderIp, plainMsg, receiver, receiver_key)

  def eavesdropMsg(self, senderIp, plainMsg, receiver, receiver_key):
    interceptorCipherMsg = encrypt(plainMsg, int.from_bytes(receiver_key, 'little')) # interceptor encrypting the plain text using the receiver encryption key
    receiver.receiveMessage(senderIp, interceptorCipherMsg)

  def modifyMsg(self, senderIp, plainMsg, receiver, receiver_key):
    interceptorCipherMsg = encrypt("Your device have been hacked :(", int.from_bytes(receiver_key, 'little')) # interceptor sends a different message to the receiver
    receiver.receiveMessage(senderIp, interceptorCipherMsg)

if __name__ == "__main__":
  alice = InternetUser("alice_ip")
  bob = InternetUser("bob_ip")

  darth = Interceptor("darth_ip", evil=True) # set evil to False to only eavesdrop messages sent
  darth.addTargetedInternetUser(alice) # remove this line to allow secure communication between alice & bob
  darth.addTargetedInternetUser(bob) # remove this line to allow secure communication between alice & bob

  alice.sendKey(bob)
  bob.sendKey(alice)

  print("Equal derived keys: ", alice.derived_key == bob.derived_key)
  print(darth.derived_keys[alice.ip] == alice.derived_key) # remove this line if an interceptor is not set
  print(darth.derived_keys[bob.ip] == bob.derived_key) # remove this line if an interceptor is not set

  alice.sendMessage(bob, "Hello Bob, how are you doing")
  print()
  bob.sendMessage(alice, "Alice have you hacked me!!!")