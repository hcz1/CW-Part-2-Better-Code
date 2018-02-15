import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.interfaces.*;

public class Client{

	public static void main(String args[]) throws Exception{

		if(args.length==3){
			String host = args[0]; // hostname of server
			int port = Integer.parseInt(args[1]); // port of server
			String userId = args[2];
				Socket s = new Socket(host, port);
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());
				DataInputStream dis = new DataInputStream(s.getInputStream());
				
				String encryptedMessage = null;
				
				dos.writeUTF(userId);
				
				try{
					encryptedMessage = dis.readUTF();
				}catch(EOFException e){
					System.out.println("User Id not found, closing connection.");
					s.close();
					System.exit(0);
				}
				
				decodeMessage(encryptedMessage, userId);

		}else{
			System.out.println("Please enter arguments like so: host port userid");
		}
	}

	public static void decodeMessage(String encryptedMessage, String userId)throws Exception{

		System.out.println("Decrypting...");
		Base64.Decoder decoder = Base64.getDecoder();
        byte[] b = decoder.decode(encryptedMessage);

        ObjectInputStream prvKey = new ObjectInputStream(new FileInputStream(userId+".prv"));
        PrivateKey privkey = (PrivateKey)prvKey.readObject();

        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, privkey);
		byte[] dec = c.doFinal(b);
			 
		String str = new String(dec, "UTF-8");
		System.out.println(str);
	}
}