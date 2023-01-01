import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class KeyStoreExample {
  private static char[] pwdArray = "password".toCharArray();
  public static void main(String[] args) throws Exception {
    //createKeyStore();
    KeyStore ks = KeyStore.getInstance("JCEKS"); //The default JKS cannot store symmetric keys 
    ks.load(new FileInputStream("my_keystore.jks"), pwdArray);
    //saveSymmetricKeys(ks);
    

  }

  private static void saveSymmetricKeys(KeyStore ks) throws NoSuchAlgorithmException, KeyStoreException {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(256); //Using AES-256
    SecretKey secretKey = generator.generateKey();
    KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
    KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(pwdArray);
    ks.setEntry("my-db-password", secret, password);
  }

  private static void createKeyStore() throws Exception {
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(null, pwdArray);
    try (FileOutputStream file = new FileOutputStream("my_keystore.jks")) {
      ks.store(file, pwdArray);
    }
  }
}
