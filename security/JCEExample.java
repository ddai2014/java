import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Examples of JCE (Java Cryptigraphic Extensions)
 */

class JCEExample {
  public static void main(String[] args) throws Exception {
    encrypt();
  }

/**
 * Symmetric Encryption 
 * DES: Data Encryption Standard
 * DESede: Triple DES Encryption
 * AES: Advanced Encryption Standard, a 128-bit block cipher supporting keys of 128, 192, and 256 bits.
 * @throws InvalidAlgorithmParameterException
 *  
 */
private static void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
        IllegalBlockSizeException, BadPaddingException {
    //Generate key
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    //generator.init(256); //Using AES-256
    SecretKey key = generator.generateKey();
    //Generate Cipher for encryption
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); //Algorithm name/Mode/Padding
    cipher.init(Cipher.ENCRYPT_MODE, key);
    String data = "testing data";
    byte[] bytes = data.getBytes();
    System.out.println("Data:");
    printBytes(bytes);
    byte[] encryptedData = cipher.doFinal(bytes);
    System.out.println("Encypted data:");
    printBytes(encryptedData);
    //Descryption
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] descrptedData = cipher.doFinal(encryptedData);
    System.out.println("Decrypted data:");
    printBytes(descrptedData);
}

  private static void printBytes(byte[] bytes) {
    System.out.println("length = " + bytes.length);
    for (byte b : bytes) {
        System.out.print(b + " ");
    }
    System.out.println();
}
}
