import base64
import zlib

import rsa
import rsa.pem
from rsa.common import NotRelativePrimeError

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import sys
import time
from datetime import datetime

import math

import random

from cryptography.hazmat.primitives.asymmetric import rsa as rsaa



from Crypto.PublicKey import ElGamal
from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import generate_probable_prime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import _serialization, serialization


def findKey(lista, keyID: bytes):
    for l in lista:
        if l.keyID == keyID:
            return l
    return None


def serializeRsaPubKey(key: rsa.PublicKey):
    lenE = math.ceil(key.e.bit_length() / 8)
    lenN = math.ceil(key.n.bit_length() / 8)
    return lenE.to_bytes(2, 'big') + lenN.to_bytes(2, 'big') + key.e.to_bytes(lenE, 'big') + key.n.to_bytes(lenN, 'big')


def deserializeRsaPubKey(array: bytes):
    start = 0
    lenE = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenN = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    e = int.from_bytes(array[start: start + lenE], 'big')
    start += lenE
    n = int.from_bytes(array[start: start + lenN], 'big')
    return rsa.PublicKey(n, e)


def serializeRsaPrivKey(key: rsa.PrivateKey):
    lenE = math.ceil(key.e.bit_length() / 8)
    lenD = math.ceil(key.d.bit_length() / 8)
    lenP = math.ceil(key.p.bit_length() / 8)
    lenQ = math.ceil(key.q.bit_length() / 8)
    return lenE.to_bytes(2, 'big') + lenD.to_bytes(2, 'big') + lenP.to_bytes(2, 'big') + lenQ.to_bytes(2,
                                                                                                       'big') + key.e.to_bytes(
        lenE, 'big') + key.d.to_bytes(lenD, 'big') + key.p.to_bytes(lenP, 'big') + key.q.to_bytes(lenQ, 'big')


def deserializeRsaPrivKey(array: bytes):
    start = 0
    lenE = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenD = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenP = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenQ = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    e = int.from_bytes(array[start: start + lenE], 'big')
    start += lenE
    d = int.from_bytes(array[start: start + lenD], 'big')
    start += lenD
    p = int.from_bytes(array[start: start + lenP], 'big')
    start += lenP
    q = int.from_bytes(array[start: start + lenQ], 'big')
    start += lenQ
    return rsa.PrivateKey(p * q, e, d, p, q)


class PrivateKeyRing:
    timestamp = 0
    keyID = 0
    publicKey = None
    cryptedPrivateKey = None
    userid = None
    username = None
    alg = 'RSA'

    def __init__(self, alg: str, publicKey: bytes, cryptedPrivateKey: bytes, userid: str, username: str, timestamp=0):
        self.timestamp = time.time_ns() if timestamp == 0 else timestamp
        self.publicKey = publicKey
        self.keyID = publicKey[-8:]
        self.cryptedPrivateKey = cryptedPrivateKey
        self.userid = userid
        self.username = username
        self.alg = alg

    def print(self):
        ret = str(datetime.fromtimestamp(self.timestamp // 1000000000)) + '|' + hex(
            int.from_bytes(self.keyID, 'big')) + '|' + hex(int.from_bytes(self.publicKey, 'big')) + '|' + hex(
            int.from_bytes(self.cryptedPrivateKey, 'big')) + '|' + self.userid + '|' + self.username + '|' + self.alg
        return ret


class PublicKeyRing:
    timestamp = 0
    keyID = 0
    publicKey = None
    userid = None
    username = None
    alg = 'RSA'

    def __init__(self, alg: str, publicKey: bytes, userid: str, username: str, timestamp=0):
        self.timestamp = time.time_ns() if timestamp == 0 else timestamp
        self.publicKey = publicKey
        self.keyID = publicKey[-8:]
        self.userid = userid
        self.username = username
        self.alg = alg

    def print(self):
        ret = str(datetime.fromtimestamp(self.timestamp // 1000000000)) + '|' + hex(
            int.from_bytes(self.keyID, 'big')) + '|' + hex(
            int.from_bytes(self.publicKey, 'big')) + '|' + self.userid + '|' + self.username + '|' + self.alg
        return ret


def sendMessage(symAlg: str, msg: str, password: str, outPath: str, pubRing: PublicKeyRing, privRing: PrivateKeyRing):
    alg = pubRing.alg
    pub = pubRing.publicKey
    cryptedPriv = privRing.cryptedPrivateKey
    key = rsa.compute_hash(password.encode(), 'MD5')
    msg = msg.encode()
    iv = b'312321z314617839'

    cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
    decry = cipher.decryptor()
    priv = decry.update(cryptedPriv) + decry.finalize()


    if alg=='RSA':
        pub = deserializeRsaPubKey(pub)
    else:
        start=0
        lenDSA = int.from_bytes(pub[start: start + 4], 'big')
        start+=4
        pub1 = pub[start: start+lenDSA]
        start+=lenDSA
        lenElG = int.from_bytes(pub[start: start + 4], 'big')
        start+=4
        pub2 = pub[start: start+lenElG]
        start+=lenElG
        pub = deserializeElGamalPubKey(pub2)
    if alg=='RSA':
        try:
            priv = deserializeRsaPrivKey(priv)
        except NotRelativePrimeError:
            print("Wrong password")
            return
    else:
        try:
            start = 0
            lenDSA = int.from_bytes(priv[start: start + 4], 'big')
            start += 4
            priv1 = priv[start: start + lenDSA]
            start += lenDSA
            priv = deserializeDsaPrivKey(priv1)
        except:
            print("Wrong password")
            return

    symetricKey = random.randint(1 << 100, (1 << 128) - 1).to_bytes(16, 'big')

    digest = rsa.compute_hash(msg, 'SHA-1')
    leadingTwoDigest = digest[0:16]
    digest = rsa.sign_hash(digest, priv, 'SHA-1')  if alg=='RSA' else priv.sign(msg, hashes.SHA1())
    lenDigest = len(digest).to_bytes(2, 'big')
    timestamp = time.time_ns().to_bytes(8, 'big')
    out = timestamp + privRing.keyID + leadingTwoDigest + lenDigest + digest + timestamp + msg

    out = zlib.compress(out)

    cipher = Cipher(algorithms.AES128(symetricKey), modes.CFB(iv)) if symAlg=="AES128" else Cipher(algorithms.CAST5(symetricKey), modes.CFB(iv[:8]))
    encr = cipher.encryptor()
    out = encr.update(out) + encr.finalize()
    symAlg = symAlg.encode()
    symetricKey = rsa.encrypt(symetricKey, pub) if alg=='RSA' else encryptElGamal(pub, symetricKey)
    lenSymKey = len(symetricKey).to_bytes(2, 'big')
    lenSymAlg = len(symAlg).to_bytes(1, 'big')
    out = lenSymAlg+ symAlg+ pubRing.keyID + lenSymKey + symetricKey + out


    out = base64.b64encode(out)


    with open(outPath, 'wb') as outt:
        outt.write(out)


def recieveMessage(path: str, password: str, loadedKeyringsPriv, loadedKeyringsPub):
    with open(path, 'rb') as inputFile:
        cripted = inputFile.read()

    cripted = base64.b64decode(cripted)

    start = 0
    lenSymAlg = int.from_bytes(cripted[start: start+1], 'big')
    start+=1
    symAlg = cripted[start: start+lenSymAlg].decode()
    start+=lenSymAlg
    myKeyID = cripted[start: start + 8]
    start += 8
    lenSymKey = int.from_bytes(cripted[start: start + 2], 'big')
    start += 2
    symetricKey = cripted[start: start + lenSymKey]
    start += lenSymKey
    iv = b'312321z314617839'
    additionalInfo = ""

    if not findKey(loadedKeyringsPriv, myKeyID):
        return "Greska: Privatni kljuc za desifrovanje nije dostupan!"
    ring = findKey(loadedKeyringsPriv, myKeyID)
    alg = ring.alg
    additionalInfo += "\n*** Poruka je bila sifrovana mojim javnim kljucem ***"
    cryptedPriv = ring.cryptedPrivateKey
    key = rsa.compute_hash(password.encode(), 'MD5')
    cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
    decry = cipher.decryptor()
    priv = decry.update(cryptedPriv) + decry.finalize()
    if alg=='RSA':
        try:
            priv = deserializeRsaPrivKey(priv)
        except NotRelativePrimeError:
            print("Wrong password")
            return
    else:
        try:
            startt = 0
            lenDSA = int.from_bytes(priv[startt: startt + 4], 'big')
            startt += 4
            priv1 = priv[startt: startt + lenDSA]
            startt += lenDSA
            lenElG = int.from_bytes(priv[startt: startt + 4], 'big')
            startt += 4
            priv2 = priv[startt: startt + lenElG]
            startt+=lenElG
            priv = deserializeElGamalPrivKey(priv2)
        except:
            print("Wrong password")
            return


    symetricKey = rsa.decrypt(symetricKey, priv) if alg=='RSA' else decryptElGamal(priv, symetricKey)

    cripted = cripted[start:]
    start = 0
    cipher = Cipher(algorithms.AES128(symetricKey), modes.CFB(iv)) if symAlg=='AES128' else Cipher(algorithms.CAST5(symetricKey), modes.CFB(iv[:8]))
    decry = cipher.decryptor()
    cripted = decry.update(cripted) + decry.finalize()


    cripted = zlib.decompress(cripted)


    timestamp1 = int.from_bytes(cripted[start: start + 8], 'big')
    start += 8
    senderKeyId = cripted[start: start + 8]
    start += 8
    leadingTwoDigest = cripted[start: start + 16]
    start += 16
    lenDigest = int.from_bytes(cripted[start: start + 2], 'big')
    start += 2
    digest = cripted[start: start + lenDigest]
    start += lenDigest
    timestamp2 = int.from_bytes(cripted[start: start + 8], 'big')
    start += 8
    msg = cripted[start:]

    if timestamp1 != timestamp2:
        return "Greska: Razliciti timestampovi u poruci i potpisu"
    additionalInfo += "\n***" + str(datetime.fromtimestamp(timestamp1 // 1000000000)) + "***"
    myDigest = rsa.compute_hash(msg, 'SHA-1')

    if myDigest[0:16] != leadingTwoDigest:
        return "Greska: Digest prva dva bajta i primljeni se razlikuju"

    if not findKey(loadedKeyringsPub, senderKeyId):
        return "Greska: Javni kljuc za autentikaciju nije dostupan"

    ring = findKey(loadedKeyringsPub, senderKeyId)
    pub = ring.publicKey
    if alg == 'RSA':
        pub = deserializeRsaPubKey(pub)
    else:
        startt = 0
        lenDSA = int.from_bytes(pub[startt: startt + 4], 'big')
        startt += 4
        pub1 = pub[startt: startt + lenDSA]
        startt += lenDSA
        pub = deserializeDsaPubKey(pub1)



    try:
        if alg=='RSA':
            rsa.verify(msg, digest, pub)
        else:
            pub.verify( digest, msg, hashes.SHA1() )
    except:
        additionalInfo='\n*** Upozorenje! Poruka je promenjena! ***\n'
        return additionalInfo
    additionalInfo += "\n*** Poruku je potpisao korisnik " + ring.userid + " ***"

    return msg.decode() + additionalInfo


def exportPubKeyRing(keyring: PublicKeyRing):
    data = rsa.pem.save_pem(serializePubKeyRing(keyring), "PGP PUBLIC KEY RING")
    with open(keyring.userid + '-PUBLIC.pem', 'wb') as pemfile:
        pemfile.write(data)


def exportPubFromPriv(keyring: PrivateKeyRing):
    keyring = PublicKeyRing(keyring.alg,keyring.publicKey, keyring.userid, keyring.username, keyring.timestamp)
    data = rsa.pem.save_pem(serializePubKeyRing(keyring), "PGP PUBLIC KEY RING")
    with open(keyring.userid + '-PUBLIC.pem', 'wb') as pemfile:
        pemfile.write(data)


def importPubKeyRing(file: str):
    with open(file, 'rb') as pemfile:
        data = pemfile.read()
    return deserializePubKeyRing(rsa.pem.load_pem(data, "PGP PUBLIC KEY RING"))


def serializePubKeyRing(keyring: PrivateKeyRing):
    ret = keyring.timestamp.to_bytes(8, 'big')
    ret += len(keyring.publicKey).to_bytes(4, 'big')
    ret += keyring.publicKey
    userid = keyring.userid.encode()
    username = keyring.username.encode()
    alg = keyring.alg.encode()
    ret += len(userid).to_bytes(1, 'big')
    ret += userid
    ret += len(username).to_bytes(1, 'big')
    ret += username
    ret += len(alg).to_bytes(1, 'big')
    ret += alg

    return ret


def deserializePubKeyRing(arr: bytes):
    start = 0
    timestamp = int.from_bytes(arr[start: start + 8], 'big')
    start += 8
    lenPubK = int.from_bytes(arr[start: start + 4], 'big')
    start += 4
    publicKey = arr[start: start + lenPubK]
    start += lenPubK
    lenUserId = int.from_bytes(arr[start: start + 1], 'big')
    start += 1
    userId = arr[start: start + lenUserId].decode()
    start += lenUserId
    lenUsername = int.from_bytes(arr[start: start + 1], 'big')
    start += 1
    username = arr[start: start + lenUsername].decode()
    start += lenUsername
    lenAlg = int.from_bytes(arr[start: start + 1], 'big')
    start+=1
    alg = arr[start: start+lenAlg].decode()
    start+=lenAlg
    return PublicKeyRing(alg, publicKey, userId, username, timestamp)


def exportPrivKeyRing(keyring: PrivateKeyRing):
    data = rsa.pem.save_pem(serializePrivKeyRing(keyring), "PGP PRIVATE KEY RING")
    with open(keyring.userid + '-PRIVATE.pem', 'wb') as pemfile:
        pemfile.write(data)


def importPrivKeyRing(file: str):
    with open(file, 'rb') as pemfile:
        data = pemfile.read()
    return deserializePrivKeyRing(rsa.pem.load_pem(data, "PGP PRIVATE KEY RING"))


def serializePrivKeyRing(keyring: PrivateKeyRing):
    ret = keyring.timestamp.to_bytes(8, 'big')
    ret += len(keyring.publicKey).to_bytes(2, 'big')
    ret += keyring.publicKey
    ret += len(keyring.cryptedPrivateKey).to_bytes(2, 'big')
    ret += keyring.cryptedPrivateKey
    userid = keyring.userid.encode()
    username = keyring.username.encode()
    alg = keyring.alg.encode()
    ret += len(userid).to_bytes(1, 'big')
    ret += userid
    ret += len(username).to_bytes(1, 'big')
    ret += username
    ret += len(alg).to_bytes(1, 'big')
    ret += alg
    return ret


def deserializePrivKeyRing(arr: bytes):
    start = 0
    timestamp = int.from_bytes(arr[start: start + 8], 'big')
    start += 8
    lenPubK = int.from_bytes(arr[start: start + 2], 'big')
    start += 2
    publicKey = arr[start: start + lenPubK]
    start += lenPubK
    lenPrivK = int.from_bytes(arr[start: start + 2], 'big')
    start += 2
    cryptedPrivateKey = arr[start: start + lenPrivK]
    start += lenPrivK
    lenUserId = int.from_bytes(arr[start: start + 1], 'big')
    start += 1
    userId = arr[start: start + lenUserId].decode()
    start += lenUserId
    lenUsername = int.from_bytes(arr[start: start + 1], 'big')
    start += 1
    username = arr[start: start + lenUsername].decode()
    start += lenUsername
    lenAlg = int.from_bytes(arr[start: start + 1], 'big')
    start+=1
    alg = arr[start: start+lenAlg].decode()
    start+=lenAlg
    return PrivateKeyRing(alg, publicKey, cryptedPrivateKey, userId, username, timestamp)


def generateRsaKeys(n):
    # return rsa.newkeys(1024)
    priv = rsaa.generate_private_key(65537, n)
    pub = priv.public_key().public_numbers()
    priv = priv.private_numbers()

    pub = rsa.PublicKey(pub.n, pub.e)
    priv = rsa.PrivateKey(pub.n, pub.e, priv.d, priv.p, priv.q)
    return (pub, priv)


def privKeyDigest(priv: bytes, password: str):
    key = rsa.compute_hash(password.encode(), 'MD5')
    iv = b'312321z314617839'
    cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    priv = encryptor.update(priv) + encryptor.finalize()
    return priv









def encryptElGamal(key: ElGamal.ElGamalKey, M: bytes):
    K = Integer(key.p)
    M = Integer(int.from_bytes(M, 'big'))
    while K.gcd(key.p) != 1 or K > key.p:
        K = generate_probable_prime(exact_bits=512)
    a = pow(key.g, K, key.p)
    b = (pow(key.y, K, key.p) * M) % key.p
    lenA = a.size_in_bytes()
    lenB = a.size_in_bytes()
    return lenA.to_bytes(2, 'big') + lenB.to_bytes(2, 'big') + a.to_bytes(lenA, 'big') + b.to_bytes(lenB, 'big')


def decryptElGamal(key: ElGamal.ElGamalKey, M: bytes):
    if not hasattr(key, 'x'):
        raise TypeError('Private key not available in this object')
    cnt = 0
    lenA = int.from_bytes(M[cnt: cnt + 2], 'big')
    cnt+=2
    lenB = int.from_bytes(M[cnt: cnt + 2], 'big')
    cnt+=2
    a = int.from_bytes(M[cnt: cnt + lenA], 'big')
    cnt+=lenA
    b = int.from_bytes(M[cnt: cnt + lenB], 'big')
    M= [a,b]
    r = Integer.random_range(min_inclusive=2,
                             max_exclusive=key.p - 1,
                             randfunc=key._randfunc)
    a_blind = (pow(key.g, r, key.p) * M[0]) % key.p
    ax = pow(a_blind, key.x, key.p)
    plaintext_blind = (ax.inverse(key.p) * M[1]) % key.p
    plaintext = (plaintext_blind * pow(key.y, r, key.p)) % key.p
    return plaintext.to_bytes(0, 'big')


def serializeElGamalPubKey(key: ElGamal.ElGamalKey):
    lenP = key.p.size_in_bytes()
    lenG = key.g.size_in_bytes()
    lenY = key.y.size_in_bytes()
    return lenP.to_bytes(2, 'big') + lenG.to_bytes(2, 'big') + lenY.to_bytes(2, 'big') + key.p.to_bytes(lenP,
                                                                                                        'big') + key.g.to_bytes(
        lenG, 'big') + key.y.to_bytes(lenY, 'big')


def serializeElGamalPrivKey(key: ElGamal.ElGamalKey):
    lenP = key.p.size_in_bytes()
    lenG = key.g.size_in_bytes()
    lenY = key.y.size_in_bytes()
    lenX = key.x.size_in_bytes()
    return lenP.to_bytes(2, 'big') + lenG.to_bytes(2, 'big') + lenY.to_bytes(2, 'big') + lenX.to_bytes(2,
                                                                                                       'big') + key.p.to_bytes(
        lenP, 'big') + key.g.to_bytes(lenG, 'big') + key.y.to_bytes(lenY, 'big') + key.x.to_bytes(lenX, 'big')


def deserializeElGamalPubKey(array: bytes):
    start = 0
    lenP = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenG = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenY = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    p = int.from_bytes(array[start: start + lenP], 'big')
    start += lenP
    g = int.from_bytes(array[start: start + lenG], 'big')
    start += lenG
    y = int.from_bytes(array[start: start + lenY], 'big')
    return ElGamal.construct((p, g, y))


def deserializeElGamalPrivKey(array: bytes):
    start = 0
    lenP = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenG = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenY = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    lenX = int.from_bytes(array[start: start + 2], 'big')
    start += 2
    p = int.from_bytes(array[start: start + lenP], 'big')
    start += lenP
    g = int.from_bytes(array[start: start + lenG], 'big')
    start += lenG
    y = int.from_bytes(array[start: start + lenY], 'big')
    start += lenY
    x = int.from_bytes(array[start: start + lenX], 'big')
    return ElGamal.construct((p, g, y, x))


def serializeDsaPubKey(key: DSAPublicKey):
    return key.public_bytes(_serialization.Encoding.PEM, _serialization.PublicFormat.SubjectPublicKeyInfo)


def serializeDsaPrivKey(key: DSAPrivateKey):
    return key.private_bytes(_serialization.Encoding.PEM, _serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())

def deserializeDsaPubKey(key: bytes):
    return load_pem_public_key(key)

def deserializeDsaPrivKey(key: bytes):
    return load_pem_private_key(key, None)

def generateElgamalKeys(n):
    priv = ElGamal.generate(n, None)
    return (priv.publickey(), priv)

def generateDsaKeys(n):
    priv = dsa.generate_private_key(key_size=n)
    return (priv.public_key(), priv)


"""
private_key = dsa.generate_private_key(
    key_size=1024,
)
data = b"this is some data I'd like to sign"
private_key = deserializeDsaPrivKey(serializeDsaPrivKey(private_key))
signature = private_key.sign(
    data,
    hashes.SHA256()
)
public_key = private_key.public_key()
public_key = deserializeDsaPubKey(serializeDsaPubKey(public_key))
try:
    public_key.verify(
        signature,
        data,
        hashes.SHA256()
    )
except:
    print('Wrong')
"""
"""
k = ElGamal.generate(1024, None)
M = 'Ovo je poruka.txt'
C = encryptElGamal(k, M)
print(C)
k = serializeElGamalPrivKey(k)
k = deserializeElGamalPrivKey(k)
print(decryptElGamal(k, C))"""
