import java.io.DataInputStream;
import java.io.InputStream;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class adds a layer of AES encryption to a DataInputStream.
 * @author andrew
 */
public class SDDRDataReader extends DataInputStream {
	InputStream in;
	byte[] key;
	public SDDRDataReader(InputStream in, byte[] key) {
		super(in);
		this.in = in;
		this.key = key;
	}

	/**
	 * Recieve a payload size from the sender as an unencrypted int
	 * @return The size of the next payload
	 * @throws Exception 
	 */
	private int recv_size() throws Exception {
		byte[] buf = new byte[4];
		int bytes_recieved = 0;
		while(bytes_recieved < 4) {
			int this_read = in.read(buf, bytes_recieved, 4 - bytes_recieved);
			if(this_read == -1) {
	    		throw new Exception("Connection error");
	    	} else {
	    		bytes_recieved += this_read;
	    	}
		}
		int size = 0;
		for(int i = 0; i < 4; ++i) {
			size |= buf[i] << (i << 3) & 0xFF << (i << 3);
		}
		return size;
	}
	
	/**
	 * Implemented as BufferedReader's next() function to read a String
	 * @return The String sent from the remote user
	 */
	public String readString() {
		String ret = null;
		try {
			// Get the length of the payload
			int len = recv_size();
			
			// Recieve the payload
			byte[] buf = new byte[len];
			int bytesRead = 0;
			while(bytesRead < len) {
				bytesRead += in.read(buf, bytesRead, len - bytesRead);
			}
			
			// Decrypt the payload, create String
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec ks = new SecretKeySpec(key, "AES");
			c.init(Cipher.DECRYPT_MODE, ks);
			ret =  new String(c.doFinal(buf), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}
	
	/**
	 * Read data from remote user, decrypt it and return it
	 * @return Decrypted data
	 */
	public byte[] readData() {
		byte[] plainText = new byte[1];
		try {
			// Get the length of the payload and unencrypted data
			int payload_len = recv_size();
			int data_len = recv_size();
			
			// Recieve the payload
			byte[] buf = new byte[payload_len];
			int bytesRead = 0;
			while(bytesRead < payload_len) {
				bytesRead += in.read(buf, bytesRead, payload_len - bytesRead);
			}
			
			// Decrypt the payload
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec ks = new SecretKeySpec(key, "AES");
			c.init(Cipher.DECRYPT_MODE, ks);
			plainText = new byte[c.getOutputSize(payload_len)];
			int ptLength = c.update(buf,0,payload_len, plainText);
			ptLength += c.doFinal(plainText, ptLength);
			
			// Truncate the data to its original size
			plainText = Arrays.copyOf(plainText, data_len);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return plainText;
	}
}
