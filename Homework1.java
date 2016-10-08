
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 *
 * @author 
 */
public class Homework1 {
    public static void main(String[] args) {
        System.out.println("Welcome to Richard's Encryption Homework assignment!");
        Scanner sc = new Scanner(System.in);
        while(true){
        System.out.print("Enter the type of crypto that you would like to use: (\"AES\", \"RSA\", or \"BLOWFISH\") ");
        String type = sc.nextLine().toLowerCase();
            if(type.equals("aes")) {
                aesCrypto(sc);
                break;
            }
            else if(type.equals("rsa")) {
                rsaCrypto(sc);
                break;
            }
            else if(type.equals("blowfish")) {
                blowfishCrypto(sc);
                break;
            }
            else {
                System.out.println("You entered an incorrect algorithm name, please try again.");
            }
        }
        /*//what i initially tried, but don't think is correct for RSA.
        try {
            Provider p = new BouncyCastleProvider();
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", p);
            System.out.println("Correct");
            
            kg.initialize(2048, new SecureRandom());
            KeyPair rsa = kg.generateKeyPair();
            //now we have generated the keypair with RSA'S public and private keys.
            
            BigInteger e = new BigInteger(rsa.getPublic().getEncoded());
            
            System.out.println("Please enter a string that you would like to encrypt using RSA: ");
            String m = sc.nextLine();
            byte[] tempAr = m.getBytes();
            BigInteger messageInt = new BigInteger(tempAr);
            
            messageInt.modPow(e, n);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("RSA Algorithm not Recognized.");
        }*/
    }

    private static void aesCrypto(Scanner sc) {
        try {
            Provider BC = new BouncyCastleProvider();
            KeyGenerator kg = KeyGenerator.getInstance("AES", BC);
            
            kg.init(128, new SecureRandom());
            SecretKey sharedAes = kg.generateKey();//now we have created a 128 bit AES key.
            SecureRandom sr = new SecureRandom();
            byte[] IV = new byte[16];
            sr.nextBytes(IV);
            //Cipher aes = Cipher.getInstance("AES/CBC/NOPADDING", BC);
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING", BC);
            IvParameterSpec spec = new IvParameterSpec(IV);
            aes.init(Cipher.ENCRYPT_MODE, sharedAes, spec);//initializing the cipher.
            
            
            
            //now encrypt some data given by the user.
            System.out.print("Please enter a string of data that you would like to encrypt: ");
            String message = sc.nextLine();
            byte[] temp = message.getBytes();
            byte[] C = aes.doFinal(temp);
            String cipherText = new String(C);
            System.out.println("\nHere is your cipher text: " + cipherText + "\n");
            
            System.out.println("Good luck finding out what that means!!\n");
            
            //now initialize decryption process.
            Cipher aesDec = Cipher.getInstance("AES/CBC/PKCS5PADDING", BC);
            aesDec.init(Cipher.DECRYPT_MODE, sharedAes, spec);
            String decryptedM = new String(aesDec.doFinal(C));
            
            System.out.println("BUT WAIT, We know the secret key!!!");
            System.out.print("Decrypted message: " + decryptedM + "\n\n");
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void rsaCrypto(Scanner sc) {
        try {
            Provider p = new BouncyCastleProvider();
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", p);
            
            kg.initialize(2048);//initializing the generators to create 2048 bit keys.
            KeyPair rsaKeys = kg.generateKeyPair();
            Cipher rsaEnc = Cipher.getInstance("RSA", p);
            rsaEnc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
            
            
            
            //now we get some data from the user to encrypt.
            System.out.print("Please enter a string of data that you would like to encrypt: ");
            String m = sc.nextLine();
            byte[] temp = m.getBytes();
            byte[] c = rsaEnc.doFinal(temp);
            String cText = new String(c);
            
            System.out.println("\nHere is your cipher text: " + cText + "\n");
            
            System.out.println("Good luck finding out what that means!!\n");
            Cipher rsaDec = Cipher.getInstance("RSA", p);
            rsaDec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
            String decryptedM = new String(rsaDec.doFinal(c));
            
            System.out.println("BUT WAIT, We know the secret key!!!");
            System.out.print("Decrypted message: " + decryptedM + "\n\n");
            
            Signature sig = Signature.getInstance("SHA256withRSA", p);
            sig.initSign(rsaKeys.getPrivate(), new SecureRandom());
            sig.update(temp);
            byte[] actualSig = sig.sign();
            //String x = new String(actualSig);
            //System.out.println("Your signature is: " + x);
            
            //System.out.println(sig.verify(actualSig)); need to initialize for verification?
            
            sig.initVerify(rsaKeys.getPublic());
            //System.out.println(sig.verify(actualSig)); false for some reason
            
            sig.update(temp); //not sure why i need to do an update here, buffer must not contain temp after initverify or sig.sign()
            System.out.println("True if signature is verified to come from this program, false otherwise: " + sig.verify(actualSig));
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void blowfishCrypto(Scanner sc) {
        try {
            Provider BC = new BouncyCastleProvider();
            KeyGenerator kg = KeyGenerator.getInstance("Blowfish", BC);
            
            kg.init(128, new SecureRandom());
            SecretKey sharedBF = kg.generateKey();//now we have created a 128 bit AES key.
            SecureRandom sr = new SecureRandom();
            byte[] IV = new byte[8];
            sr.nextBytes(IV);
            //Cipher aes = Cipher.getInstance("Blowfish/CBC/NOPADDING", BC);
            Cipher blowfish = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING", BC);
            IvParameterSpec spec = new IvParameterSpec(IV);
            blowfish.init(Cipher.ENCRYPT_MODE, sharedBF, spec);//initializing the cipher.
            
            
            
            //now encrypt some data given by the user.
            System.out.print("Please enter a string of data that you would like to encrypt: ");
            String message = sc.nextLine();
            byte[] temp = message.getBytes();
            byte[] C = blowfish.doFinal(temp);
            String cipherText = new String(C);
            System.out.println("\nHere is your cipher text: " + cipherText + "\n");
            
            System.out.println("Good luck finding out what that means!!\n");
            
            //now initialize decryption process.
            Cipher blowfishDec = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING", BC);
            blowfishDec.init(Cipher.DECRYPT_MODE, sharedBF, spec);
            String decryptedM = new String(blowfishDec.doFinal(C));
            
            System.out.println("BUT WAIT, We know the secret key!!!");
            System.out.print("Decrypted message: " + decryptedM + "\n\n");
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (InvalidAlgorithmParameterException ex) {
            //Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Homework1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
