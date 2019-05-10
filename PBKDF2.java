package anonymisering;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 {
	
	HashMap<String,String> storage = new HashMap<>();
	
	public String getGenerated(String toBeHashed) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String generated = generateStrongPasswordHash(toBeHashed);
		storage.put(toBeHashed, generated);
		return generated;
	}
	
	public HashMap<String,String> getStorage(){
		return storage;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException{
        String  originalPassword = "hei";
        String generatedSecuredPasswordHash1 = generateStrongPasswordHash(originalPassword);
        
        String alternativePassword = "hei";
        String generatedSecuredPasswordHash2 = generateStrongPasswordHash(alternativePassword);
        System.out.println(generatedSecuredPasswordHash1);     
	    
        boolean matched = validatePassword("hei", generatedSecuredPasswordHash1);
	    System.out.println(matched);
	    
	    boolean match = generatedSecuredPasswordHash1.equals(generatedSecuredPasswordHash2);
	     
	    matched = validatePassword("password1", generatedSecuredPasswordHash2);
	    System.out.println("her " + match);
	}
 
	private static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException{
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);
		byte[] salt = fromHex(parts[1]);
		byte[] hash = fromHex(parts[2]);
     
		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] testHash = skf.generateSecret(spec).getEncoded();
     
		int diff = hash.length ^ testHash.length;
		for(int i = 0; i < hash.length && i < testHash.length; i++){
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}
	
	private static byte[] fromHex(String hex) throws NoSuchAlgorithmException{
	    byte[] bytes = new byte[hex.length() / 2];
	    for(int i = 0; i<bytes.length ;i++){
	        bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
	    }
	    return bytes;
	}

    private static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException{
        int iterations = 1000;
        char[] chars = password.toCharArray();
//      byte[] salt = getSalt();
        byte[] salt = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
         
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
 //       return iterations + ":" + toHex(salt) + ":" + toHex(hash);
        return toHex(hash);
    }
     
    private static byte[] getSalt() throws NoSuchAlgorithmException{
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }
     
    private static String toHex(byte[] array) throws NoSuchAlgorithmException{
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }
        else{
            return hex;
        }
    }

}
