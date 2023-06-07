
# end-to-end-encrypted-p2p-chat


## Part 1: Application of basic cryptographic functions.
You can check the .ipynb in ./part1

### 1) Generation of public-private key pairs.
#### Task : 
Generate an RSA public-private key pair. 𝐾+ and 𝐾−. The length of the keys should be at least 1024 bits (the number of bits in the modulus).

<p align="center"><img src="../docs/1.png" alt="workflow" width="800"/></p>


<p align="center"><img src="../docs/2.png" alt="workflow" width="800"/></p>


<p align="center"><img src="../docs/3.png" alt="workflow" width="800"/></p>
___

### 2) Generation of Symmetric keys
#### Task : 
Generate a 256 bit symmetric key 𝐾𝑆 using a secure key derivation function. Encypt them with 𝐾+, print the results, and then decrypt them with 𝐾−.


<p align="center"><img src="../docs/4.png" alt="workflow" width="800"/></p>
<p align="center"><img src="../docs/5.png" alt="workflow" width="800"/></p>


### 3) Generation and Verification of Digital Signature
#### Task :
Consider any text message of more than 100 characters. Apply SHA256 Hash algorithm (Obtain the message digest, 𝐻(𝑚)). Then encrypt it with 𝐾𝐴−. (Thus generate a digital signature.) Then verify the digital signature. (Decrypt it with 𝐾𝐴+ , apply Hash algorithm to the message, compare).


<p align="center"><img src="../docs/6.png" alt="workflow" width="800"/></p>

### 4) AES Encryption/Decryption
#### Task : 
Generate any text message of more than 100 characters. Generate a random Initialization Vector (IV). Encrypt the message with AES (256 bit key) in CBC mode. Then decrypt the ciphertext, and show that it is the same as the plaintext. 


<p align="center"><img src="../docs/7.png" alt="workflow" width="800"/></p>

### 5) Message Authentication Codes
#### Task : 
Generate a message authentication code (HMAC-SHA256) using any of the symmetric keys.


<p align="center"><img src="../docs/8.png" alt="workflow" width="800"/></p>

## Part 2: P2P Messaging With End-to-End Security

<p align="center"><img src="../docs/15.png" alt="workflow" width="800"/></p>

This part has 3 main sections: 
- Creation of public keys and certificates
- Handshake process 
- Chat loop.

### Creation of Public Keys and Certificates
At the beginning of this part, the user checks if he/she has public and private keys. If there is no key for this user, user generates public and private keys by using the generation functions in the first part.
After key generation, the user checks for certification. If there is no certificate available in the database, the user asks the server to create a certificate.
Server gets the request, creates a certification for the user. Server saves the certificate to the database and then it returns the user a copy of this certificate.

### Handshake Process
User1 will try to engage in a conversation with user2. In order to achieve this, user1 needs to send a hello+certification message. User1 gets his certification and creates a string “Hello. Then user1 concats these two variables to obtain a single message variable. User1 will use this message to generate a MAC (HMAC-SHA256).

<p align="center"><img src="../docs/13.png" alt="workflow" width="800"/></p>

### Chat Loop

Two users will send messages to each other by creating a message text, obtaining a MAC (HMAC-SHA256) and encrypting the message by AES-CBC encryption.

<p align="center"><img src="../docs/14.png" alt="workflow" width="800"/></p>