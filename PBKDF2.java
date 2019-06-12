package anonymisering;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 {
	
	//Hashes the input 'toBeHashed'.	
	public String getGenerated(String toBeHashed) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String generated = generateStrongPasswordHash(toBeHashed);
		return generated;
	}

	//Hashes 'password' with the salt and iterations.
    private static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException{
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
         
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }
    
    //Converts from bytes to hexadecimal.
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
