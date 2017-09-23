// https://www.mkyong.com/java/java-hybrid-cryptography-example/

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyGen {
    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String instance;
    
    public KeyGen(int keyLength, String instance) throws NoSuchAlgorithmException, NoSuchProviderException{
        this.setInstance(instance);
        this.keyGen = KeyPairGenerator.getInstance(instance);
        this.keyGen.initialize(keyLength);
    }
    
    public void createKeys(){
        this.pair       = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey  = pair.getPublic();
    }
    
    /**
     * @return PrivateKey 
     */
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
    
    public String getInstance(){
        return this.instance;
    }
    
    private void setInstance(String instance){
        this.instance = instance;
    }

    /**
     * @return PublicKey 
     */
    public PublicKey getPublicKey() {
        return this.publicKey;
    }
    
    public byte[] getPrivateKeyBytes(){
        return this.getPrivateKey().getEncoded();
    }
    
    public byte[] getPublicKeyBytes(){
        return this.getPublicKey().getEncoded();
    }
    
    public String getPrivateKeyString(){
        byte[] key = this.getPrivateKey().getEncoded();
        return new String(key);
    }
    
    public String getPublicKeyString(){
        byte[] key = this.getPublicKey().getEncoded();
        return new String(key);
    }    
}