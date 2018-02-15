import java.io.*;
import java.security.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.util.*;
import java.net.*;


public class Server {

	public static void main(String[] args) throws Exception{
		
		if (args.length==1){
			
			cipherText();
			System.out.println("Encryption Successful");

			int port = Integer.parseInt(args[0]);

			ServerSocket ss = new ServerSocket(port);
			System.out.println("Waiting incoming connection...");

			while(true){
				Socket s = ss.accept();
				System.out.println("Connected User ");

				DataInputStream dis = new DataInputStream(s.getInputStream());
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());

				String userId = null;

				try {
					while ((userId = dis.readUTF()) != null) {
						FileInputStream cipherText = new FileInputStream("ciphertext.txt");
						DataInputStream cipherTextIn = new DataInputStream(cipherText);
						BufferedReader cipherTextBr = new BufferedReader(new InputStreamReader(cipherTextIn));

							//System.out.println(userId);

						String outputId = digestId(userId);

						String line = null;
						boolean foundUser = false;

						while((line=cipherTextBr.readLine())!= null){
							String targetId = line.split(" ")[0].trim();
							String encMessage = null;
							if(targetId.equals(outputId)){
								encMessage = line.split(" ")[1];
								dos.writeUTF(encMessage);
								foundUser=true;
								break;
							}			
						}
						if(foundUser==false){
							System.out.println("User not found, closing connection.");
							s.close();
						}
					}
				}
				catch(IOException e) {
					System.err.println("Client closed its connection.");
				}
			}
			
		}else{
			System.out.println("Please enter arguments like so: port");
		}
	}

	public static void cipherText() throws Exception{
			//user Id's					
		FileInputStream userIdData = new FileInputStream("userid.txt");
		DataInputStream userIdIn = new DataInputStream(userIdData);
		BufferedReader userIdBr = new BufferedReader(new InputStreamReader(userIdIn));

			//plain text message
		FileInputStream plainText = new FileInputStream("plaintext.txt");
		DataInputStream plainTextIn = new DataInputStream(plainText);
		BufferedReader plainTextData = new BufferedReader(new InputStreamReader(plainTextIn));

			//output to ciphertext.txt
		FileOutputStream cipherFile = new FileOutputStream("ciphertext.txt");
		DataOutputStream cipherData = new DataOutputStream(cipherFile);

		String idContent;
		String messageContent;
		String newLine = System.getProperty("line.separator");
		System.out.println("Encryption Started...");

			//loops until either file is not null - stops when either file has no more lines 
		while(((idContent=userIdBr.readLine())!= null) && ((messageContent=plainTextData.readLine())!= null)){
			String uIdPlain = idContent;
					//System.out.println(uIdPlain);
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] idDigest = md.digest(idContent.getBytes());
			BigInteger number = new BigInteger(1, idDigest);
			String hashtext = number.toString(16);
			String outputId = hashtext.substring(0,8);
					//System.out.println(hashtext.substring(0,8));
					//System.out.println(messageContent);

			ObjectInputStream pubKey = new ObjectInputStream(new FileInputStream(uIdPlain+".pub"));

			PublicKey pubkey = (PublicKey)pubKey.readObject();

			byte[] messageByte = messageContent.getBytes("UTF8");

			Base64.Encoder encoder = Base64.getEncoder();

					//start cipher
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.ENCRYPT_MODE, pubkey);
			byte[] enc = c.doFinal(messageByte);

					//base 64 encode 
			String encodedMessage = encoder.encodeToString(enc);
					//System.out.println(encodedMessage);


			cipherData.writeBytes(outputId);
			cipherData.writeChars(" ");
			cipherData.writeBytes(encodedMessage);
			cipherData.writeBytes(newLine);
			cipherData.flush();
		}
	}

	public static String digestId(String userId)throws Exception{

		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] idDigest = md.digest(userId.getBytes());
		BigInteger number = new BigInteger(1, idDigest);
		String hashtext = number.toString(16);
		String outputId = hashtext.substring(0,8);

		return outputId;
	}
}



