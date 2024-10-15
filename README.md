# Security-and-Risk-Coursework

## Table of Contents
1. [Description](#description)
2. [Running the Code](#running-the-code)
3. [Example Usage](#example-usage)
4. [Final Remarks](#final-remarks)

## Description
This university coursework involves implementing various security-related tasks. The coursework is divided into 3 main tasks:
- Implementation of Hill Cipher
- Simulation of the Diffie-Hellman Man-in-the-Middle attack
- Creation and verification of an Elliptic Curve Digital Signature

For more detailed information, please refer to the [`coursework-description.pdf`](./coursework-description.pdf)

## Running the Code
Each task is implemented in a separate Python file. To run a specific task, execute the corresponding Python file. For example, to run Task 1:
```bash
python3 src/task1.py
```

## Example Usage
1. **Hill Cipher**<br>
   You will be prompted to enter plaintext, and the ciphertext will be displayed after encryption using Hill Cipher. Note: Only capital letters are encrypted; other characters remain unchanged.
   <br><br>
   ![image](https://github.com/user-attachments/assets/3a00ab68-db1c-4970-a57e-b25ef4aecbd0)

2. **Diffie Hellman Man-in-the-Middle attack**<br>
  This task simulates a scenario where two users, Alice and Bob, exchange encrypted messages using Diffie-Hellman, while an interceptor (Darth) intercepts their public keys. Darth establishes secret keys with both Alice and Bob separately, allowing him to intercept and manipulate messages exchanged between them.<br><br>
  ![image](https://github.com/user-attachments/assets/526a70c6-6046-4289-b680-32b17296167f)<br>
  In the output, Darth intercepts Alice's and Bob's public keys, establishing separate secret keys with each. The shared keys between Alice and Bob are not equal, while the keys shared between Darth and Alice/Bob are equal. When Alice sends a message to Bob, Darth intercepts the message, decrypts it using his secret shared key with Alice, modifies it, encrypts it using his shared secret key with Bob, and sends it to Bob. Bob’s response follows the same pattern.<br><br>
  ![image](https://github.com/user-attachments/assets/02eff30e-8d88-46f7-9da8-6d3b0e57bb18)

4. **Elliptic Curve Digital Signature**<br>
In this task, public and private keys are generated using elliptic curve cryptography algorithm. The code hashes a predefined text using SHA-256 and creates a digital signature by encrypting the hash value with the private key. The signature is verified by decrypting it with the public key and comparing the resulting hash with the original hash value.<br><br>
![image](https://github.com/user-attachments/assets/9d75efce-da67-4cdc-be1c-ebb7defeb9bc)


## Final Remarks
If you would like you can read through the [`report.pdf`](./report.pdf) detailing how each task is implemented and working.
