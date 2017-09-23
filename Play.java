/**
 * @todo (1) Generate 2 public-key / private-key pairs, one for encryption/decryption and one for signing/verifying. 
 * @todo Take a file as input and call the appropriate routines to hash and sign it, and also to encrypt it with a symmetric key and then encrypt the symmetric key with the public key of a recipient.
 * @todo In addition, your program must be able to input a protected file, decrypt it, hash it, and verify the digital signature using the originator’s public verification key.
 * During the lab demonstration of your program, the TA will supply a file to be protected. The TA will observe the protection of an unprotected file, and the un-protection of a protected file.
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.nio.file.Files;

import java.nio.file.Paths;

import java.io.*;
// import java.security.SecureRandom;
// import java.security.KeyPairGenerator;
// import java.security.NoSuchProviderException;
// import java.security.KeyPair;
// import java.security.PublicKey;
// import java.security.PrivateKey;
// import java.security.Signature;
import javax.crypto.KeyGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.*;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.SignatureException;

public class Play {
    private static int KEY_SIZE             = 2048;
    private static String ALICE_PUBLIC_KEY  = "Keypairs/alice_public"; // KeyPair/publicKey_Alice"
    private static String ALICE_PRIVATE_KEY = "Keypairs/alice_private"; // KeyPair/privateKey_Alice
    private static String BOB_PUBLIC_KEY    = "Keypairs/bob_public"; // KeyPair/publicKey_Bob
    private static String BOB_PRIVATE_KEY   = "Keypairs/bob_private"; // KeyPair/privateKey_Bob
    private static String KEY_INSTANCE      = "RSA";
    
    // encryption key
    private static int    SECRET_LENGTH_BYTES       = 16; // 16, 24, 32
    private static String SECRET_KEY_SPEC_ALGO      = "AES";
    private static String SECRET_KEY_PATH           = "SecretKeys/SecretSymKey"; // OneKey/secretKey
    private static String SECRET_KEY_PATH_ENCRYPTED = "SecretKeys/SecretSymKeyEncrypted";
    private static String SECRET_KEY_PATH_DECRYPTED = "SecretKeys/SecretSymKeyDecrypted";
    
    // protectme
    private static String PAYLOAD           = "UnprotectedFiles/photo.png";
    private static String PAYLOAD_ENCRYPTED = "EncryptedFiles/photo_encrypted.png";
    private static String PAYLOAD_DECRYPTED = "DecryptedFiles/photo_decrypted.png";
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException{
        // SimpleIO.writeContent("files/file.txt", "Hello world 222");
        // String contents = SimpleIO.readContent("files/file.txt");
        // System.out.println(contents);
        
        // create keys 
        KeyGen keys_alice = new KeyGen(KEY_SIZE, KEY_INSTANCE);
        KeyGen keys_bob   = new KeyGen(KEY_SIZE, KEY_INSTANCE);
        keys_alice.createKeys();
        keys_bob.createKeys();
        
        // write the keys to files
        SimpleIO.writeContent(ALICE_PUBLIC_KEY,  keys_alice.getPublicKeyBytes());
        SimpleIO.writeContent(ALICE_PRIVATE_KEY, keys_alice.getPrivateKeyBytes());
        SimpleIO.writeContent(BOB_PUBLIC_KEY,    keys_bob.getPublicKeyBytes());
        SimpleIO.writeContent(BOB_PRIVATE_KEY,   keys_bob.getPrivateKeyBytes());
        
        // generate symmetric keys
        SymKeyGen secretKey = new SymKeyGen(SECRET_LENGTH_BYTES, SECRET_KEY_SPEC_ALGO);
        SimpleIO.writeContent(SECRET_KEY_PATH, secretKey.getKeyBytes());
        
        // generate symmetric key, public and private keys from files
        
        PrivateKey bobPrivateKey  = CryptManager.getPrivateKey(BOB_PRIVATE_KEY, KEY_INSTANCE);
        PublicKey  bobPublicKey  = CryptManager.getPublicKey(BOB_PUBLIC_KEY, KEY_INSTANCE);
        File       bobPrivateKeyFile = new File(BOB_PRIVATE_KEY);
        File       bobPublicKeyFile  = new File(BOB_PUBLIC_KEY);
        
        PrivateKey alicePrivateKey  = CryptManager.getPrivateKey(ALICE_PRIVATE_KEY, KEY_INSTANCE);
        PublicKey  alicePublicKey  = CryptManager.getPublicKey(ALICE_PUBLIC_KEY, KEY_INSTANCE);
        File       alicePrivateKeyFile = new File(ALICE_PRIVATE_KEY);
        File       alicePublicKeyFile  = new File(ALICE_PUBLIC_KEY);
        
        
        // StartEncryption startEnc = new StartEncryption();

        File            secretKeyFile          = new File(SECRET_KEY_PATH);
        SecretKeySpec   secret                 = CryptManager.getSecretKey(secretKeyFile, SECRET_KEY_SPEC_ALGO);
        File            secretKeyFileEncrypted = new File(SECRET_KEY_PATH_ENCRYPTED);
        
        // create the encrypted file
        File unprotected_file = new File(PAYLOAD);
        File protected_file   = new File(PAYLOAD_ENCRYPTED);
        File output           = new File(PAYLOAD_DECRYPTED);
        CryptManager.encryptKey(bobPublicKey, secretKeyFile, secretKeyFileEncrypted, KEY_INSTANCE);
        CryptManager.encryptData(unprotected_file, protected_file, secret, SECRET_KEY_SPEC_ALGO);
        
        // create the decryption secret
        File secretEncryptedFile = new File(SECRET_KEY_PATH_ENCRYPTED);
        File secretDecryptedFile = new File(SECRET_KEY_PATH_DECRYPTED);
        // SecretKeySpec decryptedSecret = CryptManager.getSecretKey(secretDecryptedFile, SECRET_KEY_SPEC_ALGO);
        CryptManager.decryptKey(bobPrivateKey, secretEncryptedFile, secretDecryptedFile, KEY_INSTANCE);
        CryptManager.decryptData(protected_file, output, secret, SECRET_KEY_SPEC_ALGO);
                
    }

}