package PKIServer;
//EGEHAN DOÐAN
import DatabaseManager.*;

import java.util.Base64;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class Certificate {
	private String name;
	private String email;
	private String validUntil;
	private byte[] publicKey;
	public Certificate(String name, String email, String validUntil, byte[] publicKey){
		this.name=name;
		this.email=email;
		this.validUntil=validUntil;
		this.publicKey = publicKey;
	}
	
	public String toJson(){
		GsonBuilder builder = new GsonBuilder(); 
		builder.setPrettyPrinting(); 
		Gson gson = builder.create();
		return gson.toJson(this);
	}
	
	public void saveToDatabase(){
		SimpleDatabase database = new SimpleDatabase();
		String key = Base64.getEncoder().encodeToString(publicKey);
		database.insertToDatabase(name, email, key, validUntil);
		
	}
	
	public byte[] getKey(){
		return publicKey;
	}
	public String getValidUntil(){
		return validUntil;
	}
	
	
}
