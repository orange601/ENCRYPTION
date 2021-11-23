package endpoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2Util {
	public String generateStorngPasswordHash(String password, byte[] salt, int KeyStretching) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] hash = this.createHash(password, salt, KeyStretching);
		return this.toHex(hash);
	}
	
	private byte[] createHash(String password, byte[] salt, int KeyStretching) throws NoSuchAlgorithmException, InvalidKeySpecException {
		char[] chars = password.toCharArray();
		PBEKeySpec spec = new PBEKeySpec(chars, salt, KeyStretching, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return skf.generateSecret(spec).getEncoded();
	}
	
	/**
	 * @category 비밀번호 검증
	 * */
	public boolean verifyPassword(String originalPassword, String storedPassword, byte[] salt, int KeyStretching) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] originalPwHash = this.createHash(originalPassword, salt, KeyStretching);
		byte[] storedPwHash = fromHex(storedPassword);
		
        int diff = originalPwHash.length ^ storedPwHash.length;
        for (int i = 0; i < originalPwHash.length && i < storedPwHash.length; i++) {
            diff |= originalPwHash[i] ^ storedPwHash[i];
        }
		return diff == 0;
	}
    
	/**
	 * @author orange
	 * @category salt 생성 (랜덤문자열생성)
	 * */
	public  byte[] getSalt() throws NoSuchAlgorithmException {
	    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
	    byte[] salt = new byte[16];
	    sr.nextBytes(salt);
	    return salt;
	}

	/**
	 * @author orange
	 * @category byte를 16진수 문자열로 변경
	 * */
	public String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		
		int paddingLength = (array.length * 2) - hex.length();
		if(paddingLength > 0) {
		    return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
		    return hex;
		}
	}
	
	/**
	 * @author orange
	 * @category 16진수 문자열을 byte로 변경
	 * */
	public static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for(int i = 0; i < bytes.length ;i++) {
		    bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}

}
