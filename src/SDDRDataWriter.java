import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class adds a layer of AES encryption to a DataOutputStream.
 * @author andrew
 */
public class SDDRDataWriter extends DataOutputStream {
	private OutputStream out;
	byte[] key;
	public SDDRDataWriter(OutputStream out, byte[] key) {
		super(out);
		this.out = out;
		this.key = key;
	}
	
	/**
	 * Send the size of a payload as an unencrypted int
	 * @param size The size of the next payload
	 */
	private void send_size(int size) throws IOException {
		byte[] buf = new byte[4];
		for(int i = 0; i < buf.length; ++i) {
			buf[i] = (byte)((size >> (i << 3)) & 0xFF);
		}
		out.write(buf);
	}
	
	/**
	 * Implemented similar to PrintWriter's write() function to send a string
	 * @param text The String to send.
	 */
	public void writeString(String text) {
		try {
			System.out.println("writeString: " + text);
			// Encrypt String contents
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec ks = new SecretKeySpec(key, "AES");
			c.init(Cipher.ENCRYPT_MODE, ks);
			byte[] cipherText = c.doFinal(text.getBytes("UTF-8"));
			
			// Send length of payload
			send_size(cipherText.length);
			
			// Write payload
			out.write(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Send data to remote user after encrypting it
	 * @param data The data to send
	 */
	public void writeData(byte[] data) {
		try {
			// Encrypt Data contents
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec ks = new SecretKeySpec(key, "AES");
			c.init(Cipher.ENCRYPT_MODE, ks);
			byte[] cipherText = new byte[c.getOutputSize(data.length)];
			int ctLength = c.update(data,0,data.length,cipherText,0);
			ctLength += c.doFinal(cipherText, ctLength);
			
			
			//byte[] cipherData = c.doFinal(data);
			
			// Send length of payload
			//send_size(cipherData.length);
			send_size(ctLength);
			send_size(data.length);
			
			// Write payload
			out.write(cipherText);
			out.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
