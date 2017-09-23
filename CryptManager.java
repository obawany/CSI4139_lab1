/**
 * Generates the key objects from java File objects or paths. Inspired by Marilena's work found at https://www.mkyong.com/java/java-hybrid-cryptography-example/.
 */
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.io.File;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.Key;
public class CryptManager{
    
    public static PrivateKey getPrivateKey(String filename, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        byte[] keyBytes = SimpleIO.readBytes(filename);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    public static PublicKey getPublicKey(String filename, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        byte[] keyBytes = SimpleIO.readBytes(filename);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);
    }

    public static SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException{
        // byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        byte[] keyBytes = SimpleIO.readBytes(filename);
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    public static SecretKeySpec getSecretKey(File file, String algorithm) throws IOException{
        byte[] keyBytes = SimpleIO.readBytes(file);
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    /**
     * Creates an encrypted key spec provided a public key, unencrypted key file and algorithm.
     * @param byte[]        toEncrypt 
     * @param File          output    
     * @param SecretKeySpec secretKey 
     */
    public static void encryptKey(PublicKey pub, File keyFile, File encryptedKeyFile, String algorithm)  throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        System.out.println("Encrypting key for file " +keyFile.getName());
        byte[] toEncrypt = SimpleIO.readBytes(keyFile);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        SimpleIO.writeBytes(encryptedKeyFile, cipher.doFinal(toEncrypt));
    }
    
    /**
     * Writes encrypted data from an unencrypted file to an encrypted file using a secret key spec and algorithm which was created with a call to `encryptKey`.
     */
    public static void encryptData(File unencrypted, File encrypted, SecretKeySpec secret, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        System.out.println("Encrypting data for file " + unencrypted.getName() + ". ");
        Cipher cipher = Cipher.getInstance(algorithm);
        byte[] unencryptedBytes = SimpleIO.readBytes(unencrypted);
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        SimpleIO.writeBytes(encrypted, cipher.doFinal(unencryptedBytes));
    }
    
    public static void decryptKey(Key key, File encryptedSecretKey, File decryptedSecretKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        System.out.println("Decrypting key for file " +encryptedSecretKey.getName());
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] encryptedDecryptionKey = SimpleIO.readBytes(encryptedSecretKey);        
        SimpleIO.writeBytes(decryptedSecretKey, cipher.doFinal(encryptedDecryptionKey));
    }
    
    public static void decryptData(File encryptedFile, File decryptedFile, SecretKeySpec secret, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        
        System.out.println("Decrypting data for file " +encryptedFile.getName());
        byte[] encryptedData = SimpleIO.readBytes(encryptedFile);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        SimpleIO.writeBytes(decryptedFile, decryptedData);
    }
    
    
}