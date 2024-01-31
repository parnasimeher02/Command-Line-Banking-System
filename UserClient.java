
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.net.ssl.SSLSocketFactory;

public class UserClient {
	
	public static PublicKey stringToPublicKey(String pkString) {
		PublicKey publicKey=null;
		try {
			byte[] byte_pubkey  = Base64.getDecoder().decode(pkString);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			publicKey = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(byte_pubkey));
		}
		catch(Exception e) {
			System.out.println(e.getMessage());
		}
		return publicKey;
	}

    public static void main(String[] args) {	
        
        SSLSocketFactory sslSocketFactory = 
                (SSLSocketFactory)SSLSocketFactory.getDefault();
        try {
        	String serverDomain=args[0];
        	int serverPort=Integer.parseInt(args[1]);
            Socket socket = sslSocketFactory.createSocket(serverDomain, serverPort);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            try (BufferedReader bufferedReader = 
                    new BufferedReader(
                            new InputStreamReader(socket.getInputStream()))) {
                Scanner scanner = new Scanner(System.in);
                String publicKeyString=bufferedReader.readLine();
                System.out.println(publicKeyString);
                PublicKey publicKey=stringToPublicKey(publicKeyString);
                while(true){
                	System.out.println("Enter user ID:");
                    String userID = scanner.nextLine();
                    System.out.println("Enter user password:");
                    String password = scanner.nextLine();
                    String symmetricKey = RSAEncryptionWithAES.getSecretAESKeyAsString();
                    String encriptedAESKEY = RSAEncryptionWithAES.encryptAESKey(symmetricKey, publicKey);
                    password = RSAEncryptionWithAES.encryptTextUsingAES(password, symmetricKey);
                    out.println(encriptedAESKEY);
                    out.println(userID+"|"+password);
                    String outputLine;
    				outputLine = bufferedReader.readLine();
    				System.out.println(outputLine);
    				if(outputLine.equalsIgnoreCase("1")) {
    					break;
    				}
                }
    			while(true) {
    				String balance = bufferedReader.readLine();
        			System.out.println("Your account balance is "+balance+". Please select one of the following actions:\n1.Transfer\n2.Exit");
        			String ch=scanner.nextLine();
        			if(ch.equals("2")) {
        				out.println("2");
        				break;
        			}
        			out.println("1");
        			System.out.println("Enter reciever user ID:");
                    String userID = scanner.nextLine();
                    System.out.println("Enter Amount:");
                    String amount = scanner.nextLine();
                    out.println(userID+"|"+amount);
                    String outputLine = bufferedReader.readLine();
                    System.out.println(outputLine);
                    if(outputLine.equals("0"))
                    	System.out.println("Your transaction is unsuccessful.");
                    else if(outputLine.equals("1"))
                    	System.out.println("Your transaction is successful.");
    			}
    			   
            }
            
            
        } catch (Exception ex) {
        	System.out.println(ex.getMessage());
        	ex.printStackTrace();
        }
    }
    
}
