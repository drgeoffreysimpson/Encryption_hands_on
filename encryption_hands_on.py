import rsa
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#This should be used once to generate and save public and private keys to the file system
def generate_new_keys_and_write_to_file(keyname):
    # generate using 2048 bit key...could take a few seconds
    (publickey, privatekey) = rsa.newkeys(2048)

    with open(keyname + "_private_key.pem", 'wb') as private_key_file:
        private_key_file.write(privatekey.save_pkcs1("PEM"))

    with open(keyname + "_public_key.pem", "wb") as public_key_file:
        public_key_file.write(publickey.save_pkcs1("PEM"))

    return (publickey, privatekey)


#use this to load previously saved keys from the file system into memory
def load_keys_from_file(keyname):
    with open(keyname + "_private_key.pem", 'rb') as private_key_file:
        privatekey = rsa.PrivateKey.load_pkcs1(private_key_file.read())

    with open(keyname + "_public_key.pem", "rb") as public_key_file:
        publickey = rsa.PublicKey.load_pkcs1(public_key_file.read())

    return publickey, privatekey

def load_public_key_from_file(keyname):
    with open(keyname + "_public_key.pem", "rb") as public_key_file:
        publickey = rsa.PublicKey.load_pkcs1(public_key_file.read())

    return publickey


if __name__ =="__main__":
    #Example #1, create a public/private key and use it to encrypt/decrypt
    (mypublickey, myprivatekey) = generate_new_keys_and_write_to_file("YOUR_KEYNAME_GOES_HERE")

    shared_key = secrets.token_bytes(32) #this gets random numbers from the OS
    iv = secrets.token_bytes(16) #this gets random numberes from the OS

    #specify the AES algorithm
    algorithm = algorithms.AES(shared_key)

    #define two different modes we could use....use our own "KNOWN" iv so we can reproduce our encryption results.  DO NOT USE THIS IN PRODUCTION, YOUR IV SHOULD BE DIFFERENT EVERY TIME!
    mode = modes.CTR('testtesttesttest'.encode())
    gcm_mode = modes.GCM('testtesttesttest'.encode())

    # USE IT THIS WAY IN PRODUCTION ENVIRONMENT
    # mode = modes.CTR(iv)
    # gcm_mode = modes.GCM(iv)

    cipher = Cipher(algorithm, mode)
    encryptor = cipher.encryptor()

    plaintext = "secret plaintext message goes here".encode('utf-8')

    #the message gets encrypted righ here.
    encrypted_message = encryptor.update(plaintext) + encryptor.finalize()
    

    #now we are going to do the reverse and decrypt the message
    decrpytor = cipher.decryptor()
    decrypted_message = decrpytor.update(encrypted_message) + decrpytor.finalize()
    assert(plaintext == decrypted_message)

    #example #2
    #this is used to create a signature (needs private key)
    signaturetext = rsa.sign(plaintext, myprivatekey, 'SHA-1')
    # print(str(signaturetext))

    ciphertext = rsa.encrypt(plaintext, mypublickey)
    # print(ciphertext)

    decryptedtext = rsa.decrypt(ciphertext, myprivatekey)
    assert(plaintext == decryptedtext)
    print(decryptedtext)


