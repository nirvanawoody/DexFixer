package com.woody.dexfix;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.zip.Adler32;

/**
 * @author Woody nirvanawoody@gmail.com 2018-03-01
 */
public class DexFix {

	private static String inDex;
	private static String outDex;

	public static void main(String[] args) {
		if (args.length < 1 || args.length > 2) {
			System.out.println("usage:\n dexfix in.dex [out.dex]");
			return;
		}
		inDex = args[0];
		if (args.length == 1) {
			System.out.println("Overwrite input dex.");
			outDex = inDex;
		} else {
			outDex = args[1];
		}
		File file = new File(inDex);
		try {
			byte[] bytes = getBytesFromFile(file);
			// find origin checksum
			byte[] originCheckSum = getBytes(bytes, 8, 4);
			System.out.println("Origin CheckSum:");
			System.out.printf("0x%02X%02X %02X%02X\n", originCheckSum[3],
					originCheckSum[2], originCheckSum[1], originCheckSum[0]);
			// find origin signature
			byte[] originSign = getBytes(bytes, 0xC, 20);
			System.out.print("Origin Signature:\n0x");
			for (int i = 0; i < originSign.length; i += 2) {
				System.out.printf("%02X%02X ", originSign[i], originSign[i + 1]);
			}
			System.out.println();
			// get new sign
			calcSignature(bytes);
			// get new checksum
			calcChecksum(bytes);
			byte[] newCheckSum = getBytes(bytes, 8, 4);
			System.out.println("New CheckSum:");
			System.out.printf("0x%02X%02X %02X%02X\n", newCheckSum[3],
					newCheckSum[2], newCheckSum[1], newCheckSum[0]);
			// find origin signature
			byte[] newSign = getBytes(bytes, 0xC, 20);
			System.out.print("New Signature:\n0x");
			for (int i = 0; i < newSign.length; i += 2) {
				System.out.printf("%02X%02X ", newSign[i], newSign[i + 1]);
			}
			System.out.println();
			System.out.println("Write data to "+outDex);
			putBytesToFile(bytes, outDex);
			System.out.println("Success!");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] getBytes(byte[] bytes, int offset, int length) {
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = bytes[offset + i];
		}
		return result;
	}

	private static byte[] getBytesFromFile(File file) throws IOException {
		InputStream inputStream = new FileInputStream(file);
		long length = file.length();
		if (length > Integer.MAX_VALUE) {
			System.err.println("File is too long to be read.");
		}
		byte[] bytes = new byte[(int) length];
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length
				&& (numRead = inputStream.read(bytes, offset, bytes.length
						- offset)) >= 0) {
			offset += numRead;
		}
		inputStream.close();
		return bytes;
	}

	private static void calcSignature(byte bytes[]) throws Exception {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-1");
		md.update(bytes, 32, bytes.length - 32);
		int amt = md.digest(bytes, 12, 20);
		if (amt != 20) {
			throw new Exception("digeset error");
		}
	}

	private static void calcChecksum(byte bytes[]) {
		Adler32 a32 = new Adler32();
		a32.update(bytes, 0xC, bytes.length - 0xC);
		int sum = (int) a32.getValue();
		bytes[8] = (byte) sum;
		bytes[9] = (byte) (sum >> 8);
		bytes[10] = (byte) (sum >> 16);
		bytes[11] = (byte) (sum >> 24);
	}
	
	
	public static void putBytesToFile(byte[] data, String outfile) throws IOException {
        FileOutputStream fos = new FileOutputStream(outfile);
        fos.write(data, 0, data.length);
        fos.flush();
        fos.close();

    }

}
