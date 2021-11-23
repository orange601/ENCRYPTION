package endpoint;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Application {
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
		String pw = "ABC";
		
		// 1. 일반적인 SHA-256 암호화
		SHA256Util sha = new SHA256Util();
		String enc1 = sha.encrypt(pw);
		System.out.println(enc1);
		
		// 2. salt가 추가된 SHA-256 암호화, salt는 생성시 DB에 저장 후 관리 해야 한다.
		String salt2 = SHA256Util.getSalt();
		String enc2 = sha.encrypt(pw, salt2);
		System.out.println(enc2);
		
		// 3. 키 스트레칭 + salt를 사용한 SHA-256 암호화를 한다.
		int KeyStretching1 = 10;
		String salt3 = SHA256Util.getSalt();
		String enc3 = sha.encrypt(pw, salt3, KeyStretching1);
		System.out.println(enc3);
		
		// 4. BCrypt 암호화
		BCryptUtil butil = new BCryptUtil();
		String bcrypt = butil.BCrypt(pw);
		System.out.println(bcrypt);
		System.out.println("비밀번호 확인 : " + butil.checkpw(pw, bcrypt));
		
		// 5. PBKDF2Util 암호화
		PBKDF2Util putil = new PBKDF2Util();
		byte[] salt4 = putil.getSalt();
		int KeyStretching2 = 1000;
		String a = putil.generateStorngPasswordHash(pw, salt4, KeyStretching2);
		System.out.println("a : " + a);
		boolean sss = putil.verifyPassword(pw,a, salt4, KeyStretching2);
		System.out.println(sss);
		boolean rrr = putil.verifyPassword("abccc",a, salt4, KeyStretching2);
		System.out.println(rrr);
		
	}

}
