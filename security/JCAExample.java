import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Examples of JCA (Java Cryptography Architecture) inlcuding
 * Message Digest, Private/Public Key, Certification, and Signatuture
 * 
 */

class JCAExample {
    public static void main(String[] args) throws Exception {
        //listAllProviders();
        //digest();
        //keypair();
        loadCertification();
        //loadPrivateKey();
    }

    private static void loadCertification() throws Exception {
        //Load a self-signed certificate generated with following script
        //openssl req -nodes -newkey rsa:2048 -keyout mykey.key -out mycert.crt -x509 -days 365
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)factory.generateCertificate(new FileInputStream("outlook4.p7c"));
        System.out.println(certificate);
        PublicKey publicKey = certificate.getPublicKey();
        byte[] signtures = certificate.getSignature();
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(certificate.getTBSCertificate());
        boolean result = sign.verify(signtures);
        System.out.println(result);
    }

    private static void loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //Load the private key
        byte[] pkData = Files.readAllBytes(Paths.get("mykey.key"));
        String pkString = new String(pkData, Charset.defaultCharset());
        String encoded = pkString.replace("-----BEGIN PRIVATE KEY-----", "").
                                  replaceAll("\n", "").
                                  replaceAll("\r", "").
                                  replace("-----END PRIVATE KEY-----", "");
        System.out.println(encoded);
        byte[] pk = Base64.getDecoder().decode(encoded);                       

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pk);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        System.out.println(privateKey);
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
