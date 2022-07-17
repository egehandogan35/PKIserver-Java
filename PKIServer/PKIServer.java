package PKIServer;
//EGEHAN DOÐAN
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import DatabaseManager.SimpleDatabase;

public class PKIServer extends Thread {
	public static final int validityInYears = 1;
	private Socket socket;
	private static KeyPair pair;

	public PKIServer(Socket socket) {
		this.socket = socket;
	}

	public static void main(String[] args) { //Everytime Server restarts it generates a new assymetric keypair
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);

			pair = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(6000);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		while (true) {
			try {

				Socket acceptedSocket = serverSocket.accept();
				PKIServer serverThread = new PKIServer(acceptedSocket);//waits for socket connections creates a thread for every connection
				System.out.println("Established a connection");
				serverThread.start();
				System.out.println("Started thread");

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	public void run() {
		DataInputStream dIn;
		BufferedReader stringReader;
		try {

			stringReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String requestType = stringReader.readLine();
			System.out.println("read The request" + requestType); //reads request type

			if (requestType.equals("bind")) { //Creates a certificate and saves it to database
				System.out.println("Got the bind request");
				String name = stringReader.readLine();
				String email = stringReader.readLine(); //reads user identification
				System.out.println("read name and email"+name+" "+email);
				

				String clientkey = stringReader.readLine();
				byte[] key = Base64.getDecoder().decode(clientkey); //gets user public key
				
				System.out.println("Succesfully read key");
				
				
				//getting a date 1 year from now on
				Calendar cal = Calendar.getInstance();
				Date today = cal.getTime();
				cal.add(Calendar.YEAR, validityInYears); // gets the next year
				Date nextYear = cal.getTime();
				
				DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
				String strDate = dateFormat.format(nextYear);
				
				
				
				//creates certificate object
				Certificate certificate = new Certificate(name, email, strDate, key); //creastes a certificate
				certificate.saveToDatabase(); //saves it to database
				System.out.println("Succesfully saved to database");
				String certificateString = certificate.toJson(); //turns certificate object into a json string

				List<byte[]> list = new ArrayList<byte[]>();

				try { //signs it
					Signature rsa = Signature.getInstance("SHA256withRSA");

					list.add(certificateString.getBytes(StandardCharsets.UTF_8));

					PrivateKey privateKey = pair.getPrivate();

					// Sign the data using the private key
					rsa.initSign(privateKey);
					rsa.update(certificateString.getBytes());

					byte[] signature = rsa.sign();
					list.add(signature);
					ObjectOutputStream out = new ObjectOutputStream(new DataOutputStream(socket.getOutputStream()));
					out.writeObject(list);
					out.close();
					System.out.println("Sent the certificate");
				} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
					System.err.println(e.getMessage());
				}

			}
			
			if(requestType.equals("getKey")){ //Just sends servers public key as base64
				System.out.println("Got the public key request");
				DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
				byte[] publickey = pair.getPublic().getEncoded();
				
				
				System.out.println(Arrays.toString(publickey));
				
				String key = Base64.getEncoder().encodeToString(publickey);
				System.out.println(key);
				dOut.writeBytes(key+'\r');
				System.out.println("Wrote public key");
			}
			if(requestType.equals("verify")){//given name email and public key checks if the combination exists and if it does sends a verification with expiry date
				String name = stringReader.readLine();
				String email = stringReader.readLine();
				
				String clientkey = stringReader.readLine();
				byte[] key = Base64.getDecoder().decode(clientkey);
				
				System.out.println("Succesfully read key");
				
				SimpleDatabase database = new SimpleDatabase();
				ArrayList<Certificate> results = database.getEntriesForEmail(name,email);
				System.out.println("Found "+results.size()+" matching results.");
				boolean verified = false;
				String validUntil = null;
				for(int i=0; i<results.size();i++){
					if(Base64.getEncoder().encodeToString(results.get(i).getKey()).equals(Base64.getEncoder().encodeToString(key))){
						verified=true;
						validUntil = results.get(i).getValidUntil();
					}
				}
				String verifyResult = (verified)?"Yes, "+name+" - "+email+" have ownership of that key. That key expires at -"+ validUntil :"No there is no entry in our database for that name, email and key combination";

				List<byte[]> list = new ArrayList<byte[]>();

				try {
					Signature rsa = Signature.getInstance("SHA256withRSA");

					list.add(verifyResult.getBytes(StandardCharsets.UTF_8));

					PrivateKey privateKey = pair.getPrivate();

					// Sign the data using the private key
					rsa.initSign(privateKey);
					rsa.update(verifyResult.getBytes());

					byte[] signature = rsa.sign();
					list.add(signature);
					ObjectOutputStream out = new ObjectOutputStream(new DataOutputStream(socket.getOutputStream()));
					out.writeObject(list);
					out.close();
					System.out.println("Sent the verify result");
				} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
					System.err.println(e.getMessage());
				}
				
			}
			
			if(requestType.equals("getPublicKeyOf")){//gets a public key with entered name and email it ets the last entry
				String name = stringReader.readLine();
				String email = stringReader.readLine();
			
				SimpleDatabase database = new SimpleDatabase();
				ArrayList<Certificate> results = database.getEntriesForEmail(name,email);
				System.out.println("Found "+results.size()+" matching results.");
				
				String getResults=null;
				for(int i=0; i<results.size();i++){
					getResults=	Base64.getEncoder().encodeToString(results.get(i).getKey());
				}
				

				List<byte[]> list = new ArrayList<byte[]>();

				try {
					Signature rsa = Signature.getInstance("SHA256withRSA");

					list.add(getResults.getBytes(StandardCharsets.UTF_8));

					PrivateKey privateKey = pair.getPrivate();

					// Sign the data using the private key
					rsa.initSign(privateKey);
					rsa.update(getResults.getBytes());

					byte[] signature = rsa.sign();
					list.add(signature);
					ObjectOutputStream out = new ObjectOutputStream(new DataOutputStream(socket.getOutputStream()));
					out.writeObject(list);
					out.close();
					System.out.println("Sent the verify result");
				} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
					System.err.println(e.getMessage());
				}
				
			}
			

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
