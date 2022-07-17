package Client;
// EGEHAN DOÐAN
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Client {
	private static KeyPair currentPair;
	private static PublicKey serverPublicKey;
	String certificate;
	private static String username="KemoBoi";
	private static String useremail="kemoBoi@gmail.com";

	// Writes a key to a path
	public static void writeToFile(String path, byte[] key) throws IOException { //Used to write a key to a file
		File file = new File(path);
		//file.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(file);
		fos.write(key);
		fos.flush();
		fos.close();
	}

	// generates a key pair
	public static KeyPair generateAsymmetricKeys() { //generates assymmetric keys for client
		try {

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);

			KeyPair pair = keyGen.generateKeyPair();
			return pair;
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}
		return null;

	}

	public static void main(String[] args) throws InterruptedException {
		Scanner input = new Scanner(System.in);
		int portNumber = 6000;
		Socket socket=null;
		DataOutputStream dOut;
		String host = "localhost";
		byte[] publicKey;
		boolean running=true;
		while (running) { //User Interface loop
			System.out.println(
					"Please chose what you want to do? obtain-server-publickey ,create-keypair, store-keypair, read-keypair, obtain-certificate, verify-ownership&check-expired, sign-document, verify-document, change-user");
			String command = input.nextLine(); //takes command from user
			switch (command) {//decides what to do based on command
			case "create-keypair"://Sets static keypair to a newly generated keypair
				Client.currentPair = Client.generateAsymmetricKeys();
				break;
			case "store-keypair"://stores static current-keypair to two different files as public and private key
				try {
					System.out.println("Please enter a path to save private key.");
					String path = input.nextLine();
					Client.writeToFile(path + "-privateKey", currentPair.getPrivate().getEncoded());
					Client.writeToFile(path + "-publicKey", currentPair.getPublic().getEncoded());
				} catch (IOException e) {
					System.out.println("There was an error in File/io please try again.");
					e.printStackTrace();
				}
				break;
			case "read-keypair"://If it gets the same name it reads the keys from file and puts it onto static current keypair
				System.out.println("Please enter the same name that you entered for storing.");
				String name = input.nextLine();
				try {
					byte[] privateKeyBytes = Files.readAllBytes(new File(name + "-privateKey").toPath());
					byte[] publicKeyBytes = Files.readAllBytes(new File(name + "-publicKey").toPath());
					PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
					X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
					PublicKey publickey = keyFactory.generatePublic(publicKeySpec);
					currentPair = new KeyPair(publickey, privateKey);
				} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				break;

			case "obtain-certificate": //Sends unencrypted request to PKI server with name email and public key
				System.out.println("Obtaining certificate");
				publicKey = currentPair.getPublic().getEncoded();
				try {
					socket = new Socket(host, portNumber);
					dOut = new DataOutputStream(socket.getOutputStream());
					dOut.writeBytes("bind" + '\n');//Type of request
					dOut.writeBytes(username + '\n');//name
					dOut.writeBytes(useremail + '\n');//email
					System.out.println("Wrote name and email");
					String key = Base64.getEncoder().encodeToString(publicKey);
					dOut.writeBytes(key + '\n');//key in a string form in base64 format
					System.out.println("Wrote Key");

					ObjectInputStream objIn = new ObjectInputStream(new DataInputStream(socket.getInputStream())); 
					List<byte[]> list = (List<byte[]>) objIn.readObject(); //gets Certificate as a json String at 0 and Signature at 1
					System.out.println("Got the certificate");
					byte[] msg = list.get(0);
					byte[] signature = list.get(1);

					String certificate = new String(msg, StandardCharsets.UTF_8);
					System.out.println(certificate);

					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initVerify(serverPublicKey);
					sig.update(msg);

					Boolean verified = sig.verify(signature); //conforms Certificate with hopefullt previously obtained server public key

					System.out.println(verified ? "VERIFIED MESSAGE" + "\n----------------\n" + new String(msg)
							: "Could not verify the signature.");

				} catch (UnknownHostException e) {
					System.err.println("Don't know about host " + host);
				} catch (IOException e) {
					System.err.println("Couldn't get I/O for the connection to the host " + host);
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
			case "obtain-server-publickey": //gets server public key to use in various places
				System.out.println("Obtaining public key");
				try {
					socket = new Socket(host, portNumber);
					dOut = new DataOutputStream(socket.getOutputStream());
					dOut.writeBytes("getKey" + '\n'); //request type

					System.out.println("Sent obtain request");
					BufferedReader stringReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					String serverkey = stringReader.readLine(); //gets server public key as a base64 string

					System.out.println(serverkey); //Prints it as base64 ... because why not
					byte[] key = Base64.getDecoder().decode(serverkey);
					//System.out.println(Arrays.toString(key));//Prints byte array for debugging

					X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					serverPublicKey = kf.generatePublic(spec);//sets static serverPublicKey to that key
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				break;

			case "verify-ownership&check-expired": //Sends name email and a key and checks if it previously exists in database, if it does gets expirity date
				try {
					socket = new Socket(host, portNumber);
					dOut = new DataOutputStream(socket.getOutputStream());
					dOut.writeBytes("verify" + '\n');//Type of request
					dOut.writeBytes(username + '\n');
					dOut.writeBytes(useremail + '\n');

					publicKey = currentPair.getPublic().getEncoded();
					String key = Base64.getEncoder().encodeToString(publicKey);
					dOut.writeBytes(key + '\n');//writes to key to server
					System.out.println("Sent verify request");

					ObjectInputStream objIn = new ObjectInputStream(new DataInputStream(socket.getInputStream()));
					List<byte[]> list = (List<byte[]>) objIn.readObject();
					System.out.println("Got the certificate");
					byte[] msg = list.get(0);
					byte[] signature = list.get(1);

					String results = new String(msg, StandardCharsets.UTF_8);

					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initVerify(serverPublicKey);
					sig.update(msg);

					Boolean verified = sig.verify(signature);

					System.out.println(verified ? "VERIFIED MESSAGE" + "\n----------------\n" + new String(msg)
							: "Could not verify the signature.");

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;

			case "sign-document"://signs the document with current private key
				String Document = "This is a document";

				List<byte[]> list = new ArrayList<byte[]>();

				try {
					Signature rsa = Signature.getInstance("SHA256withRSA");

					list.add(Document.getBytes(StandardCharsets.UTF_8));

					PrivateKey privateKey = currentPair.getPrivate();

					// Sign the data using the private key
					rsa.initSign(privateKey);
					rsa.update(Document.getBytes());

					byte[] signature = rsa.sign();
					list.add(signature);
					ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("document"));
					out.writeObject(list);
					out.close();
					System.out.println("Created the Document");
				} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
					System.err.println(e.getMessage());
				}
				break;

			case "verify-document":
				System.out.println("If you want to verify a document that is not signed by you, change your user to who you think that document was written by.");
				ObjectInputStream objIn;
				try {
					objIn = new ObjectInputStream(new DataInputStream(new FileInputStream("document")));
					List<byte[]> documentContents = (List<byte[]>) objIn.readObject();
					
					
					
					socket = new Socket(host, portNumber);
					dOut = new DataOutputStream(socket.getOutputStream());
					dOut.writeBytes("getPublicKeyOf" + '\n');//Type of request
					dOut.writeBytes(username + '\n');
					dOut.writeBytes(useremail + '\n');

					ObjectInputStream objectIn = new ObjectInputStream(new DataInputStream(socket.getInputStream()));
					List<byte[]> certificate = (List<byte[]>) objectIn.readObject();//gets the last matching public key from server
					System.out.println("Got the certificate");
					byte[] msg = certificate.get(0);
					byte[] signature = certificate.get(1);

					String key = new String(msg, StandardCharsets.UTF_8);

					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initVerify(serverPublicKey);
					sig.update(msg);

					Boolean verified = sig.verify(signature); //verifies if public key really did come from server

					System.out.println(verified ? "VERIFIED MESSAGE" + "\n----------------\n" + key
							: "Could not verify the signature.");

					if (verified) {
						byte[] documentsPublicKeyBytes = Base64.getDecoder().decode(key); //gets the key from certificate

						X509EncodedKeySpec spec = new X509EncodedKeySpec(documentsPublicKeyBytes);
						KeyFactory kf = KeyFactory.getInstance("RSA");
						PublicKey documentsPublicKey = kf.generatePublic(spec);
						
						Signature documentSignature = Signature.getInstance("SHA256withRSA");
						documentSignature.initVerify(documentsPublicKey);
						documentSignature.update(documentContents.get(0));
						Boolean documentVerified = documentSignature.verify(documentContents.get(1)); //verifies documents was signed with matching private key with public key from server
						
						if(documentVerified){
							System.out.println("Document is verified");
						}else{
							System.out.println("Document signature doesnt match with expected one");
						}
						
					}else{
						System.out.println("Server signature doesnt match with expected one");
					}

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				break;
				
			case "change-user":
				System.out.println("Enter the username");
				username = input.nextLine();
				System.out.println("Enter the user email");
				useremail = input.nextLine();
				System.out.println("Succesfully changed user to "+username+":"+useremail+".");
				break;
				
			case "close":
				running=false;
				break;

			default:
				System.out.println("You entered an unexisting command");
				break;

			}
		}
		try {
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


}
