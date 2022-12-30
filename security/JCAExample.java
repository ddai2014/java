import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Examples of JCA (Java Cryptography Architecture) inlcuding
 * Message Digest, Public/Private Key Pair, and Signatuture
 * 
 */

class JCAExample {
    public static void main(String[] args) throws Exception {
        //listAllProviders();
        //digest();
        keypair();
    }

    private static void keypair() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        /**
         * RSA - Rivest-Shamir-Adieman
         * The public key is used to encrypt messages and the private key is used to decrypt messages. 
         * The reverse is done to create a digital signature.
         * 
         * DH
         * 
         * DSA
         * 
         */
        String algorithm = "DSA";
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(1024);
        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();
        System.out.println("Private Key = " + privateKey);
        System.out.println("Public Key = " + publicKey);

        
        // Signature is encrypted with private key and everyone with public key can verify it.
        Signature sign = Signature.getInstance(privateKey.getAlgorithm());
        sign.initSign(privateKey);
        byte[] data = {1, 2, 3, 4};
        sign.update(data);
        byte[] signedData = sign.sign();
        System.out.println("Signed data:");
        printBytes(signedData);
        
        //verifying signature using public key
        sign.initVerify(publicKey);
        sign.update(data);
        boolean verify = sign.verify(signedData);
        System.out.println(verify);





    }

    private static void digest() throws NoSuchAlgorithmException {
        MessageDigest md1 = MessageDigest.getInstance("SHA-1");
        MessageDigest md256 = MessageDigest.getInstance("SHA-256");
        MessageDigest mdmd5 = MessageDigest.getInstance("MD5");
        
        byte[] bytes1 = md1.digest("password".getBytes());
        byte[] bytes256 = md256.digest("password".getBytes());
        byte[] bytesmd5 = mdmd5.digest("password".getBytes());
        System.out.println(md1.getAlgorithm() + ", length = " + md1.getDigestLength() + " , provider = " + md1.getProvider().getName());
        printBytes(bytes1);
        System.out.println(md256.getAlgorithm() + ", length = " + md256.getDigestLength() + " , provider = " + md256.getProvider().getName());
        printBytes(bytes256);
        System.out.println(mdmd5.getAlgorithm() + ", length = " + mdmd5.getDigestLength() + " , provider = " + mdmd5.getProvider().getName());
        printBytes(bytesmd5);
    }

    private static void listAllProviders() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println("Name = " + provider.getName() + ", Info = " + provider.getInfo());
        }

    }

    private static void printBytes(byte[] bytes) {
        System.out.println("length = " + bytes.length);
        for (byte b : bytes) {
            System.out.print(b + " ");
        }
        System.out.println();
    }
}
