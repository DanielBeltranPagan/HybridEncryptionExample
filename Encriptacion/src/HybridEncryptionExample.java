import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class HybridEncryptionExample {

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Introduce un mensaje: ");
        String message = scanner.nextLine();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKeyAES = keyGenerator.generateKey();

        Cipher cipherAES = Cipher.getInstance("AES");
        cipherAES.init(Cipher.ENCRYPT_MODE, secretKeyAES);
        byte[] mensajeCifradoAES = cipherAES.doFinal(message.getBytes());

        System.out.println("\nMensaje cifrado con AES:");
        System.out.println(Base64.getEncoder().encodeToString(mensajeCifradoAES));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey clavePublicaRSA = keyPair.getPublic();
        PrivateKey clavePrivadaRSA = keyPair.getPrivate();

        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.ENCRYPT_MODE, clavePublicaRSA);
        byte[] claveAESCifrada = cipherRSA.doFinal(secretKeyAES.getEncoded());

        System.out.println("\nClave AES cifrada con RSA:");
        System.out.println(Base64.getEncoder().encodeToString(claveAESCifrada));

        cipherRSA.init(Cipher.DECRYPT_MODE, clavePrivadaRSA);
        byte[] claveAESDescifradaBytes = cipherRSA.doFinal(claveAESCifrada);

        SecretKey claveAESDescifrada = new SecretKeySpec(claveAESDescifradaBytes, "AES");

        cipherAES.init(Cipher.DECRYPT_MODE, claveAESDescifrada);
        byte[] mensajeDescifrado = cipherAES.doFinal(mensajeCifradoAES);

        System.out.println("\nMensaje descifrado:");
        System.out.println(new String(mensajeDescifrado));
    }
}
