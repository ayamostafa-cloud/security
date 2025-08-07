package security;

import java.math.BigInteger;
import java.util.Random;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RSA {

    private static BigInteger p, q, n, phi, e, d;
    private static final int CERTAIN_BIT_SIZE = 256; // For modulus size check

    public static void main(String[] args) throws Exception {
        // Step 1: Get RSA key size from user input
        int keySize = getKeySize();

        // Step 2: Generate public and private keys
        generateKeys(keySize);

        // Step 3: Read and encrypt a message
        String message = new String(Files.readAllBytes(Paths.get("message.txt")), StandardCharsets.UTF_8);
        BigInteger messageBigInt = new BigInteger(message.getBytes());

        // Check if message is smaller than the modulus 'n' (RSA works with numbers smaller than 'n')
        if (messageBigInt.compareTo(n) >= 0) {
            System.out.println("Message is too large to encrypt with the current key size.");
            return;
        }

        BigInteger encryptedMessage = encrypt(messageBigInt);

        // Step 4: Decrypt the message
        BigInteger decryptedMessage = decrypt(encryptedMessage);
        String decryptedText = new String(decryptedMessage.toByteArray(), StandardCharsets.UTF_8);

        // Step 5: Write the encrypted and decrypted messages to files
        writeToFile(encryptedMessage, decryptedText);

        // Step 6: Print the results to the console
        printConsoleOutput(message, messageBigInt, encryptedMessage, decryptedText, decryptedMessage);
    }

    // Step 1: Get RSA key size from user input
    private static int getKeySize() {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        int keySize = 0;
        while (keySize < CERTAIN_BIT_SIZE) {
            System.out.println("Enter Size");
            keySize = scanner.nextInt();
            if (keySize < CERTAIN_BIT_SIZE) {
                System.out.println("n must be greater than or equal to 256");
            }
        }
        return keySize;
    }

    // Step 2: Generate public and private keys
    private static void generateKeys(int keySize) {
        Random random = new Random();

        // Generate two large primes p and q
        p = BigInteger.probablePrime(keySize / 2, random);
        q = BigInteger.probablePrime(keySize / 2, random);

        // Calculate n = p * q
        n = p.multiply(q);

        // Calculate phi(n) = (p - 1) * (q - 1)
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Select e such that 1 < e < phi and gcd(e, phi) = 1
        e = BigInteger.valueOf(65537); // commonly used value for e
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0) {
            e = e.add(BigInteger.TWO);
        }

        // Calculate d such that d * e ≡ 1 (mod phi)
        d = e.modInverse(phi);
    }

    // Step 3: Encrypt a message
    private static BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    // Step 4: Decrypt a message
    private static BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(d, n);
    }

    // Step 5: Write the encrypted and decrypted messages to files
    private static void writeToFile(BigInteger encryptedMessage, String decryptedText) throws IOException {
        // Write encrypted message in Base64 to file
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage.toByteArray());
        Files.write(Paths.get("encryptedRSA.txt"), encryptedMessageBase64.getBytes(StandardCharsets.UTF_8));

        // Write the decrypted message to file
        Files.write(Paths.get("decryptedMessage.txt"), decryptedText.getBytes(StandardCharsets.UTF_8));
    }

    // Step 6: Print the results to the console
    private static void printConsoleOutput(String message, BigInteger messageBigInt, BigInteger encryptedMessage, String decryptedText, BigInteger decryptedMessage) {
        System.out.println("The generated public key in plaintext: " + n.toString(36));
        System.out.println("The generated public key in big integer: " + n + ", " + e);
        System.out.println("The generated private key in plaintext: " + d.toString(36));
        System.out.println("The generated private key in big integer: " + d);
        
        System.out.println("\nMessage in plaintext: " + message);
        System.out.println("Message in big integer: " + messageBigInt);

        System.out.println("\nEncrypted Cipher in Base64 (plaintext): " + Base64.getEncoder().encodeToString(encryptedMessage.toByteArray()));
        System.out.println("Encrypted Cipher in big integer: " + encryptedMessage);

        System.out.println("\nDecrypted Message in plaintext: " + decryptedText);
        System.out.println("Decrypted Message in big integer: " + decryptedMessage);
    }
}
