import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * RSA Encryting a string - a reference implementation
 * @author Justin C. Klien Keane <justin@madirish.net>
 *
 */
public class RSATest {
	 public static void main(String[] args) throws NoSuchAlgorithmException, 
	 	NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");  // Set up the key generating factory
	        
	        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4); // Initialize a 1024 bit key
	        keyGen.initialize(spec);
	        KeyPair key_pair = keyGen.genKeyPair();

	        byte[] private_key = key_pair.getPrivate().getEncoded();  // Extract the private key
	        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(private_key));
	        
	        byte[] public_key = key_pair.getPublic().getEncoded();  // Extract the public key
	        System.out.println("Public Key:  " + Base64.getEncoder().encodeToString(public_key));
	        
	        String secret_message = new String("This is my string to encrypt!");  // The secret message (must be under 117 bytes per block)
	        
	        byte cipher_text[] = null;
	        Cipher rsa = Cipher.getInstance("RSA");  // Set up the type of encryption
	        try {
		        System.out.println("Encrypting the string: " + secret_message);
	        	rsa.init(Cipher.ENCRYPT_MODE, key_pair.getPublic());  // Set mode and key to use
	        	cipher_text = rsa.doFinal(secret_message.getBytes());  // Encrypt the string
		        System.out.println("Ciphertext: " + cipher_text.toString());
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	        }
	        
	        try {
	        	rsa.init(Cipher.DECRYPT_MODE, key_pair.getPrivate());  // Set mode and key to use
	        	byte plain_text[] = rsa.doFinal(cipher_text);  // Decrypt the ciphertext
	        	System.out.println("Plaintext: " + new String(plain_text, StandardCharsets.UTF_8));
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	        }
	    }
}

