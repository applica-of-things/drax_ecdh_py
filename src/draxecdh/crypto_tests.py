import unittest
import numpy as np

import crypto

class TestCaseCrypto(unittest.TestCase):

    def createRandomData(self, n):
        data = np.zeros((n), dtype=np.uint8)
        for i in np.arange(n):
            data[i] = np.random.randint(0, 254)
        return data

    def test_padding(self):
        print("padding test ...")
        
        data = "Matera2019 la citta del futuro err"
        padded_data = crypto.crypto_pkcs7pad(np.frombuffer(data.encode(), dtype=np.uint8))
        expected_padded_data = np.array([77, 97, 116, 101, 114, 
            97, 50, 48, 49, 57, 32, 108, 97, 32, 99, 105, 116, 
            116, 97, 32, 100, 101, 108, 32, 102, 117, 116, 117, 
            114, 111, 32, 101, 114, 114, 14, 14, 14, 14, 14, 
            14, 14, 14, 14, 14, 14, 14, 14, 14], dtype=np.uint8)
        
        assert (padded_data == expected_padded_data).all()
    
    def test_AES_crypt_decrypt(self):
        print("AES encryption test ...")

        plain_text = "Matera2019 la citta del futuro err"
        key_str = "lamiachiave.2020lamiachiave.2020" # 32 chars for 256 bits

        data = np.array([ord(i) for i in plain_text], dtype=np.uint8)
        data = np.frombuffer(plain_text.encode(), dtype=np.uint8) # convert str to np arr
        padded_data = crypto.crypto_pkcs7pad(data)
        key = np.array([ord(i) for i in key_str], dtype=np.uint8) # convert str to np arr

        encrypted_data = crypto.crypto_aesEncrypt(padded_data, key, len(key)*8)    
        
        decrypted_data = crypto.crypto_aesDecrypt(encrypted_data, key, len(key)*8)
        unpadded_data = crypto.crypto_pkcs7unpad(decrypted_data)
        decrypted_text = ''.join(map(chr, unpadded_data))
        
        self.assertTrue(decrypted_text == plain_text)

#    def _test_md5(self):
#        print("MD5 encryption test ...")
#        
#        plain_text = "bruno"
#        expected_hash = "e3928a3bc4be46516aa33a79bbdfdb08"
#        computed_md5 = hashlib.md5(plain_text.encode('utf-8')).hexdigest()
#        
#        self.assertTrue(expected_hash == computed_md5)

    def test_key_gen_fixed_private_key(self):
        print("keygen test with fixed prv key...")

        my_prv = np.zeros((crypto.crypto_privateKeySize()), dtype=np.uint8)
        
        my_prv[:] = [33, 21, 4, 250, 33, 21, 4, 250, 33, 21, 4, 250, 
            33, 21, 4, 250, 33, 21, 4, 250, 33, 21, 4, 250]

        my_pub = crypto.crypto_generateKeyPair(my_prv)

        expected_pub =  np.array([210, 121, 5, 63, 159, 170, 200, 55, 246, 65, 56, 89, 57, 
            115, 126, 48, 86, 208, 191, 251, 7, 0, 0, 0, 170, 160, 157, 237, 78, 120, 
            91, 50, 135, 174, 14, 100, 203, 64, 244, 115, 105, 142, 214, 181, 6, 0, 0, 0], dtype=np.uint8)
        
        self.assertTrue((my_pub == expected_pub).all())

    def test_key_gen(self):
        print("keygen test...")
        
        my_prv = self.createRandomData(crypto.crypto_privateKeySize())

        cloud_prv = self.createRandomData(crypto.crypto_privateKeySize()) 

        my_pub = crypto.crypto_generateKeyPair(my_prv)
        cloud_pub = crypto.crypto_generateKeyPair(cloud_prv)

        assert (my_pub != None).all() and (cloud_pub != None).all()

    def test_sign_unsign(self):
        print("sign_unsign test...")
        data_str = "bruno fortuto bruno fortunato ciao ciao cioa 1242556"
        data_size = len(data_str)
    
        my_prv_hex = "a7a81b6f2d4376cce2a37e1c2051ec3bf9e11d9603000000"
        my_pub_hex = "72b708696a89ff49099b7d803221cdcec9c57f69070000004c25154fee44b60c83259b260180957c5f99459203000000"
        cloud_prv_hex = "1be0a4ba29fad1398cf4260593626579986c830601000000"
        cloud_pub_hex = "ddd18a4ef40a51504237e542935b919ea141e2d704000000b0fb60735125ff7adddc881494687ad6f0a12fd905000000"

        criminal_prv = self.createRandomData(crypto.crypto_privateKeySize())

        # fix private key to generate public key
        criminal_prv = np.array([128, 3, 0, 0, 128, 3, 0, 0, 128, 3, 0, 0, 128, 3, 0, 0, 
            128, 3, 0, 0, 128, 3, 0, 0], dtype=np.uint8)
        
        criminal_pub_expected = np.array([98, 147, 190, 123, 187, 71, 106, 134, 107, 253, 
            163, 17, 45, 66, 63, 14, 237, 111, 37, 45, 3, 0, 0, 0, 70, 228, 180, 188, 229, 
            38, 158, 173, 171, 240, 252, 45, 52, 186, 219, 192, 123, 78, 210, 8, 4, 0, 0, 
            0], dtype=np.uint8)

        criminal_pub = crypto.crypto_generateKeyPair(criminal_prv)

        assert((criminal_pub == criminal_pub_expected).all())
            
        localPrivateKey = np.frombuffer(bytearray.fromhex(my_prv_hex), dtype=np.uint8)
        cloudPubKey = np.frombuffer(bytearray.fromhex(cloud_pub_hex), dtype=np.uint8)
        
        data = np.frombuffer(data_str.encode(), dtype=np.uint8)
        signed_data = crypto.crypto_sign(localPrivateKey, cloudPubKey, data)

        cloudPrivateKey = np.frombuffer(bytearray.fromhex(cloud_prv_hex), dtype=np.uint8)
        localPubKey = np.frombuffer(bytearray.fromhex(my_pub_hex), dtype=np.uint8) 
        
        unsigned_data = crypto.crypto_unsign(cloudPrivateKey, localPubKey, signed_data)
        
        unsigned_data_str = "".join(map(chr, unsigned_data))
        
        assert data_str == unsigned_data_str

if __name__ == '__main__':
    # all tests
    testSuite = unittest.TestSuite()
    testSuite.addTest(TestCaseCrypto("test_padding"))
    testSuite.addTest(TestCaseCrypto("test_AES_crypt_decrypt"))
    testSuite.addTest(TestCaseCrypto("test_key_gen"))
    testSuite.addTest(TestCaseCrypto("test_key_gen_fixed_private_key"))
    testSuite.addTest(TestCaseCrypto("test_sign_unsign"))
    unittest.TextTestRunner().run(testSuite)