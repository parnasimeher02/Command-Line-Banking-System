
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLServerSocketFactory;

public class BankServer {

	public static Map<String, Object> generateKeys() {
		Map<String, Object> keys = null;
		try {
			keys = RSAEncryptionWithAES.getRSAKeys();
			PublicKey publicKey = (PublicKey) keys.get("public");
			FileWriter myWriter = new FileWriter("public.txt");
			myWriter.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
			myWriter.close();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return keys;
	}
	
	

	public static String getMd5(String input) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] messageDigest = md.digest(input.getBytes());
			BigInteger no = new BigInteger(1, messageDigest);
			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static boolean checkPassword(String userID, String password) {
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader("passwd.txt"));
			String line = reader.readLine();
			while (line != null) {
				String s[] = line.split("\\|");
				System.out.println(password + "\n" + s[1]);
				if (userID.equalsIgnoreCase(s[0]) && password.equalsIgnoreCase(s[1])) {
					reader.close();
					return true;
				}
				line = reader.readLine();
			}

			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	public static Map<String, Integer> getAmount() {
		BufferedReader reader;
		Map<String, Integer> map = new HashMap<>();
		try {
			reader = new BufferedReader(new FileReader("balance.txt"));
			String line = reader.readLine();
			while (line != null) {
				String s[] = line.split("\\|");
				map.put(s[0], Integer.parseInt(s[1]));
				line = reader.readLine();
			}

			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return map;
	}

	public static void mapToFile(Map<String, Integer> map) {
		try {
			String s = "";
			for (Map.Entry<String, Integer> entry : map.entrySet()) {
				s = s + entry.getKey() + "|" + entry.getValue() + "\n";
			}
			FileWriter myWriter = new FileWriter("balance.txt");
			myWriter.write(s);
			myWriter.close();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
	}

	public static void main(String[] args) {

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

		try {
			Map<String, Object> keys = RSAEncryptionWithAES.getRSAKeys();
			PublicKey publicKey = (PublicKey) keys.get("public");
			PrivateKey privateKey = (PrivateKey) keys.get("private");
			int serverPort = Integer.parseInt(args[0]);
			ServerSocket sslServerSocket = sslServerSocketFactory.createServerSocket(serverPort);
			System.out.println("SSL ServerSocket started");
			System.out.println(sslServerSocket.toString());
			while (true) {
				Socket socket = sslServerSocket.accept();
				System.out.println("ServerSocket accepted");

				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				try (BufferedReader bufferedReader = new BufferedReader(
						new InputStreamReader(socket.getInputStream()))) {
					String line;
					String userID = "";
					out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
					while (true) {
						String key = bufferedReader.readLine();
						System.out.println(key);
						line = bufferedReader.readLine();
						System.out.println(line);
						String password = "";
						if (line.contains("|")) {
							String s[] = line.split("\\|");
							userID = s[0];
							password = s[1];
							
							key = RSAEncryptionWithAES.decryptAESKey(key, privateKey);
							password = RSAEncryptionWithAES.decryptTextUsingAES(password, key);
							if (checkPassword(userID, getMd5(password))) {
								out.println(1);
								break;
							}
							out.println(0);
						}
					}
					while (true) {
						Map<String, Integer> m = getAmount();
						int balance = m.get(userID);
						out.println(balance);
						line = bufferedReader.readLine();
						System.out.println(line);
						if (line.equals("2"))
							break;
						line = bufferedReader.readLine();
						System.out.println(line);
						String reciever = "";
						int amount = 0;
						if (line.contains("|")) {
							String s[] = line.split("\\|");
							reciever = s[0];
							amount = Integer.parseInt(s[1]);
						}
						if (balance < amount) {
							out.println("0");
						} else {
							balance -= amount;
							int n = m.get(reciever) + amount;
							m.put(reciever, n);
							m.put(userID, balance);
							mapToFile(m);
							out.println("1");
						}
					}
				}
			}

		} catch (IOException ex) {
			System.out.println(ex.getMessage());
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}

	}

}
