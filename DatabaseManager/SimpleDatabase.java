package DatabaseManager;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;

import PKIServer.Certificate;
//EGEHAN DOÐAN

public class SimpleDatabase {
	

	/** The name of the MySQL account to use (or empty for anonymous) */
	private final String userName = "root";

	/** The password for the MySQL account (or empty for anonymous) */
	private final String password = "root";

	/** The name of the computer running MySQL */
	private final String serverName = "localhost";

	/** The port of the MySQL server (default is 3306) */
	private final int portNumber = 3306;

	private final String dbName = "PublicKeys";

	private final String tableName = "Certificate";

	public Connection getConnection() throws SQLException {
		Connection conn = null;
		Properties connectionProps = new Properties();
		connectionProps.put("user", this.userName);
		connectionProps.put("password", this.password);

		conn = DriverManager.getConnection(
				"jdbc:mysql://" + this.serverName + ":" + this.portNumber + "/" + this.dbName, connectionProps);

		return conn;
	}

	public boolean executeUpdate(Connection conn, String command) throws SQLException {
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
			stmt.executeUpdate(command); // This will throw a SQLException if it fails
			return true;
		} finally {

			// This will run whether we throw an exception or not
			if (stmt != null) {
				stmt.close();
			}
		}
	}

	/**
	 * Connect to MySQL and do some stuff.
	 */
	public void createTable() {

		// Connect to MySQL
		Connection conn = null;
		try {
			conn = this.getConnection();
			System.out.println("Connected to database");
		} catch (SQLException e) {
			System.out.println("ERROR: Could not connect to the database");
			e.printStackTrace();
			return;
		}

		// Create a table
		try {
			String createString = "CREATE DATABASE "+dbName;
			this.executeUpdate(conn, createString);
			System.out.println("Created a database");
			createString = "CREATE TABLE " + this.tableName + "(CERTIFICATEID INTEGER, USERNAME TINYTEXT, EMAIL TINYTEXT,PUBLICKEY TEXT,VALIDITY TEXT,PRIMARY KEY (CERTIFICATEID)) ";
			this.executeUpdate(conn, createString);
			System.out.println("Created a table");
		} catch (SQLException e) {
			System.out.println("ERROR: Could not create the table");
			e.printStackTrace();
			return;
		}

	}

	public void insertToDatabase(String name, String email, String key, String validUntil) {
		int count=0;
		String query = "SELECT COUNT(*) FROM "+tableName+";";
		try {
			Statement statement = this.getConnection().createStatement();
			ResultSet rs = statement.executeQuery(query);
			while(rs.next()){
				count = rs.getInt(1);
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		
		}
		String insertString = "INSERT INTO "+tableName +" VALUES ("+(++count)+","+ "\"" + name + "\","
				+ "\"" + email + "\","+ "\""  + key  + "\","+ "\""  + validUntil+  "\""+ ")";
		// Connect to MySQL
		Connection conn = null;
		try {
			conn = this.getConnection();
			System.out.println("Connected to database");
		} catch (SQLException e) {
			System.out.println("ERROR: Could not connect to the database");
			e.printStackTrace();
			return;
		}
		try {
			this.executeUpdate(conn, insertString);
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public ArrayList<Certificate> getEntriesForEmail(String name,String email){   
		String query;
		ArrayList<Certificate> results = new ArrayList<Certificate>();
		query = "Select * FROM Certificate WHERE EMAIL=\""+email+"\" AND USERNAME=\""+name+"\";";//SQLInjectiona maÄŸruz kalabilir
		
		try {
			Statement statement = this.getConnection().createStatement();
			ResultSet rs = statement.executeQuery(query);
			while(rs.next()){
				String nameresult = rs.getString("USERNAME");
				String EMAIL = rs.getString("EMAIL");
				String publickey = rs.getString("PUBLICKEY");
				String validuntil = rs.getString("VALIDITY");
				byte[] key   = Base64.getDecoder().decode(publickey);
				results.add(new Certificate(nameresult,EMAIL,validuntil, key));
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		
		}
		return results;
		
	} 
	
	

	public static void main(String[] args) {
		new SimpleDatabase().createTable();

		

	}
}