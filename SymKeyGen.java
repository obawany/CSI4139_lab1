
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SymKeyGen {
    private SecretKeySpec secretKey;

    public SymKeyGen(int length, String algorithm) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecureRandom rnd = new SecureRandom();
        byte [] key = new byte [length];
        rnd.nextBytes(key);
        this.secretKey = new SecretKeySpec(key, algorithm);
    }
    
    public SecretKeySpec getKey(){
        return this.secretKey;
    }
    
    public byte[] getKeyBytes(){
        return this.getKey().getEncoded();
    }

}
