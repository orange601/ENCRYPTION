package endpoint;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class BCryptUtil {
	
	public String BCrypt(String password) {
		return BCrypt.hashpw(password, BCrypt.gensalt());
	}
	
	public boolean checkpw(String password, String encrypted) {
		return BCrypt.checkpw(password, encrypted);
	}

}
