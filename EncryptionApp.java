import java.util.Scanner;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EncryptionApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        ArrayList<EncryptedEntry> StoredEntries = new ArrayList<>();

        while (running) {
            System.out.println("\n Encryption Program Menu ");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. View Stored Data");
            System.out.println("4. Exit");
            System.out.println("Select an option (1-4): ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    System.out.print("Enter text to encrypt: ");
                    String plainText = scanner.nextLine();

                    System.out.print("What is this for (e.g., Google Passwprd): ");
                    String description = scanner.nextLine();

                    String encrypted = Encryptor.encrypt(plainText);

                    StoredEntries.add(new EncryptedEntry(description, encrypted));
                    System.out.println("Text encrypted and successfully stored.");
                   break;
                
                case 2:
                    if (StoredEntries.isEmpty()) {
                        System.out.println("No stored entries to decrypt.");
                    } else {
                        System.out.println("\n--- Select entry to decrypt ---");
                        for (int i = 0; i < StoredEntries.size(); i++) {
                            System.out.println((i + 1) + ". " + StoredEntries.get(i).getDescription());
                        }

                        System.out.print("Enter the number of the entry to decrypt: ");
                        int index = scanner.nextInt();
                        scanner.nextLine();

                        if (index < 1 || index > StoredEntries.size()) {
                            System.out.println("Invalid Selection.");
                        } else {
                            EncryptedEntry selected = StoredEntries.get(index - 1);
                            String decrypted = Encryptor.decrypt(selected.getEncryptedText());
                            System.out.println("Decrypted Text: " + decrypted);
                        }

                    }
                   break;

                case 3:
                    if (StoredEntries.isEmpty()) {
                        System.out.println("No stored data found.");
                    } else {
                        System.out.println("\n---Stored Data ---");
                        for (int i = 0; i < StoredEntries.size(); i++) {
                            EncryptedEntry entry = StoredEntries.get(i);
                            System.out.println((i +1) + ". " + entry.getDescription() + " - " + entry.getEncryptedText());
                        }
                    }
                  break;

                case 4:
                    running = false;
                    System.out.println("Exiting program.");
                    break;
                
                default:
                    System.out.println("Invalid choice. Select 1-4.");
                    
            }
        }

        scanner.close();

    }
}

 class EncryptedEntry {
    private String description;
    private String encryptedText;

    public EncryptedEntry(String description, String encryptedText) {
        this.description = description;
        this.encryptedText = encryptedText;
    }

    public String getDescription() {
        return description;
    }

    public String getEncryptedText() {
        return encryptedText;
    }
}

class Encryptor {
    private static final String SECRET_KEY = "1234567890123456";

    public static String encrypt(String input) {
        try {
            SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static String decrypt(String encryptedInput) {
        try {
            SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] decoded = Base64.getDecoder().decode(encryptedInput);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}