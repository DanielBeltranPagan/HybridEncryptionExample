import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class HybridEncryptionExample {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Introduce un mensaje: ");
        String message = scanner.nextLine();

        KeyPair keyPair = generarParClavesRSA();
        SecretKey claveAES = generarClaveAES();

        byte[] mensajeCifrado = cifrarMensajeAES(message, claveAES);
        byte[] claveAESCifrada = cifrarClaveAESConRSA(claveAES, keyPair.getPublic());

        System.out.println("\nMensaje cifrado: " + Base64.getEncoder().encodeToString(mensajeCifrado));
        System.out.println("Clave AES cifrada: " + Base64.getEncoder().encodeToString(claveAESCifrada));

        SecretKey claveRecuperada = descifrarClaveAESConRSA(claveAESCifrada, keyPair.getPrivate());
        String mensajeFinal = descifrarMensajeAES(mensajeCifrado, claveRecuperada);

        System.out.println("\nMensaje descifrado: " + mensajeFinal);
    }

    private static SecretKey generarClaveAES() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    private static byte[] cifrarMensajeAES(String mensaje, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, clave);
        return cipher.doFinal(mensaje.getBytes(StandardCharsets.UTF_8));
    }

    private static String descifrarMensajeAES(byte[] datos, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, clave);
        byte[] original = cipher.doFinal(datos);
        return new String(original, StandardCharsets.UTF_8);
    }

    private static KeyPair generarParClavesRSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] cifrarClaveAESConRSA(SecretKey claveAES, PublicKey publica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publica);
        return cipher.doFinal(claveAES.getEncoded());
    }

    private static SecretKey descifrarClaveAESConRSA(byte[] claveCifrada, PrivateKey privada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privada);
        byte[] claveDescifradaBytes = cipher.doFinal(claveCifrada);
        return new SecretKeySpec(claveDescifradaBytes, "AES");
    }
}