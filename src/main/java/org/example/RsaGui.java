package org.example;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

public class RsaGui extends JFrame {

    private JTextField pField, qField, dField;
    private JTextField inputFileField, outputFileField;
    private JTextArea outputArea;
    private JButton encryptButton, decryptButton;
    private JButton chooseInputButton, chooseOutputButton;
    private File selectedInputFile;
    private File selectedOutputFile;

    
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger MAX_N_FOR_SHORT = BigInteger.valueOf(65535); 

    public RsaGui() {
        super("Shaminko RSA");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
        setLocationRelativeTo(null); 

        
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.1;
        inputPanel.add(new JLabel("p (prime):"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.9;
        pField = new JTextField(15);
        inputPanel.add(pField, gbc);

        
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.1;
        inputPanel.add(new JLabel("q (prime, != p):"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.9;
        qField = new JTextField(15);
        inputPanel.add(qField, gbc);

        
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.1;
        inputPanel.add(new JLabel("d (private key Kc):"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 0.9;
        dField = new JTextField(15);
        inputPanel.add(dField, gbc);

        
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.1;
        inputPanel.add(new JLabel("Input File:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 0.7;
        inputFileField = new JTextField(30);
        inputFileField.setEditable(false);
        inputPanel.add(inputFileField, gbc);
        gbc.gridx = 2; gbc.gridy = 3; gbc.weightx = 0.2;
        chooseInputButton = new JButton("Choose...");
        inputPanel.add(chooseInputButton, gbc);

        
        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0.1;
        inputPanel.add(new JLabel("Output File:"), gbc);
        gbc.gridx = 1; gbc.gridy = 4; gbc.weightx = 0.7;
        outputFileField = new JTextField(30);
        outputFileField.setEditable(false);
        inputPanel.add(outputFileField, gbc);
        gbc.gridx = 2; gbc.gridy = 4; gbc.weightx = 0.2;
        chooseOutputButton = new JButton("Choose...");
        inputPanel.add(chooseOutputButton, gbc);

        
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(outputArea);

        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        
        setLayout(new BorderLayout(10, 10));
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        
        chooseInputButton.addActionListener(e -> chooseFile(inputFileField, true));
        chooseOutputButton.addActionListener(e -> chooseFile(outputFileField, false));
        encryptButton.addActionListener(e -> performEncryption());
        decryptButton.addActionListener(e -> performDecryption());
    }

    
    private void chooseFile(JTextField targetField, boolean isInput) {
        JFileChooser fileChooser = new JFileChooser();
        int result;
        if (isInput) {
            result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedInputFile = fileChooser.getSelectedFile();
                targetField.setText(selectedInputFile.getAbsolutePath());
            }
        } else {
            result = fileChooser.showSaveDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedOutputFile = fileChooser.getSelectedFile();
                targetField.setText(selectedOutputFile.getAbsolutePath());
            }
        }
    }

    private Object[] validateInputs(BigInteger p, BigInteger q, BigInteger privateKey) {
        outputArea.setText(""); 

        
        if (!p.isProbablePrime(50)) {
            return new Object[]{false, null, null, "Error: p is not likely prime."};
        }
        if (!q.isProbablePrime(50)) {
            return new Object[]{false, null, null, "Error: q is not likely prime."};
        }
        
        if (p.equals(q)) {
            return new Object[]{false, null, null, "Error: p and q must be distinct."};
        }

        BigInteger n = p.multiply(q);
        BigInteger phi = eulerFunction(p, q);

        if (privateKey.compareTo(ZERO) <= 0 || privateKey.compareTo(phi) >= 0) {
            return new Object[]{false, n, phi, "Error: private key d must be > 0 and < phi(n) = " + phi};
        }
        
        BigInteger[] extendedGCD = euclid(privateKey, phi);
        BigInteger gcd = extendedGCD[1];
        if (!gcd.equals(ONE)) {
            return new Object[]{false, n, phi, "Error: private key d is not relatively prime to phi(n). gcd(d, phi) = " + gcd};
        }
        
        if (n.compareTo(MAX_N_FOR_SHORT) > 0) {
            return new Object[]{false, n, phi, "Error: n = p*q = " + n + " is too large. Must be <= " + MAX_N_FOR_SHORT + " for 16-bit encrypted blocks."};
        }

        return new Object[]{true, n, phi, null}; 
    }

    private byte[] readFile(File file) {
        if (file == null || !file.exists()) {
            showError("Input file not selected or does not exist.");
            return null;
        }
        try {
            long length = file.length();
            
            if (length > Integer.MAX_VALUE) {
                showError("File is too large.");
                return null;
            }
            byte[] buffer = new byte[(int) length];
            try (FileInputStream fis = new FileInputStream(file);
                 BufferedInputStream bis = new BufferedInputStream(fis)) {
                int bytesRead = bis.read(buffer);
                if (bytesRead != length) {
                    
                    showError("Could not read the entire file.");
                    return null;
                }
            }
            return buffer;
        } catch (IOException e) {
            showError("Error reading input file: " + e.getMessage());
            e.printStackTrace();
            return null;
        } catch (SecurityException e) {
            showError("Permission denied to read input file: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private boolean writeEncryptedFile(File file, List<BigInteger> encryptedData) {
        if (file == null) {
            showError("Output file not selected.");
            return false;
        }
        try (FileOutputStream fos = new FileOutputStream(file);
             DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(fos))) {
            for (BigInteger block : encryptedData) {
                
                dos.writeShort(block.shortValue());
            }
            return true;
        } catch (IOException e) {
            showError("Error writing encrypted file: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (SecurityException e) {
            showError("Permission denied to write output file: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private boolean writeDecryptedFile(File file, byte[] decryptedData) {
        if (file == null) {
            showError("Output file not selected.");
            return false;
        }
        try (FileOutputStream fos = new FileOutputStream(file);
             BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            bos.write(decryptedData);
            return true;
        } catch (IOException e) {
            showError("Error writing decrypted file: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (SecurityException e) {
            showError("Permission denied to write output file: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private void performEncryption() {
        try {
            
            BigInteger p = new BigInteger(pField.getText().trim());
            BigInteger q = new BigInteger(qField.getText().trim());
            BigInteger d = new BigInteger(dField.getText().trim()); 

            
            Object[] validationResult = validateInputs(p, q, d);
            boolean isValid = (Boolean) validationResult[0];
            BigInteger n = (BigInteger) validationResult[1];
            BigInteger phi = (BigInteger) validationResult[2];
            String errorMessage = (String) validationResult[3];

            if (!isValid) {
                showError(errorMessage);
                return;
            }

            BigInteger[] extendedGCD = euclid(d, phi); 
            BigInteger e = extendedGCD[0].mod(phi);
            
            if (e.signum() < 0) {
                e = e.add(phi);
            }

            outputArea.setText("Parameters:\n");
            outputArea.append(" p = " + p + "\n");
            outputArea.append(" q = " + q + "\n");
            outputArea.append(" d (Kc) = " + d + "\n");
            outputArea.append(" n = p*q = " + n + "\n");
            outputArea.append(" phi(n) = " + phi + "\n");
            outputArea.append(" e (Ko - Public Key) = " + e + "\n");
            outputArea.append(" gcd(d, phi) = " + extendedGCD[1] + "\n\n"); 

            byte[] fileBytes = readFile(selectedInputFile);
            if (fileBytes == null) {
                return; 
            }
            if (fileBytes.length == 0) {
                showError("Input file is empty.");
                return;
            }

            
            outputArea.append("Encrypting file: " + selectedInputFile.getName() + "\n");
            outputArea.append("Encrypted data (16-bit blocks as decimal shorts):\n");
            List<BigInteger> encryptedBlocks = new ArrayList<>();
            StringBuilder encryptedTextOutput = new StringBuilder();

            for (int i = 0; i < fileBytes.length; i++) {
                byte currentByte = fileBytes[i];
                
                BigInteger m = BigInteger.valueOf(Byte.toUnsignedInt(currentByte));

                
                BigInteger c = fastExponentialModular(m, e, n);
                encryptedBlocks.add(c);

                
                encryptedTextOutput.append(c.shortValue()); 
                if (i < fileBytes.length - 1) {
                    encryptedTextOutput.append(" ");
                }
                if ((i + 1) % 10 == 0) { 
                    encryptedTextOutput.append("\n");
                }
            }
            outputArea.append(encryptedTextOutput.toString() + "\n\n");

            
            if (selectedOutputFile == null) {
                showError("Please choose an output file location.");
                return;
            }
            boolean success = writeEncryptedFile(selectedOutputFile, encryptedBlocks);
            if (success) {
                outputArea.append("Encryption successful.\nEncrypted data saved to: " + selectedOutputFile.getAbsolutePath());
                JOptionPane.showMessageDialog(this, "Encryption Complete!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                outputArea.append("Encryption failed. Could not write output file.");
            }

        } catch (NumberFormatException ex) {
            showError("Invalid number format for p, q, or d. Please enter valid integers.");
        } catch (Exception ex) {
            showError("An unexpected error occurred during encryption: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    
    private void performDecryption() {
        try {
            
            BigInteger p = new BigInteger(pField.getText().trim());
            BigInteger q = new BigInteger(qField.getText().trim());
            BigInteger d = new BigInteger(dField.getText().trim()); 

            Object[] validationResult = validateInputs(p, q, d);
            boolean isValid = (Boolean) validationResult[0];
            BigInteger n = (BigInteger) validationResult[1];
            
            String errorMessage = (String) validationResult[3];

            if (!isValid) {
                showError(errorMessage);
                return;
            }

            outputArea.setText("Parameters for Decryption:\n");
            outputArea.append(" p = " + p + "\n");
            outputArea.append(" q = " + q + "\n");
            outputArea.append(" d (Kc) = " + d + "\n");
            outputArea.append(" n (modulus r) = p*q = " + n + "\n\n");


            
            if (selectedInputFile == null || !selectedInputFile.exists()) {
                showError("Encrypted input file not selected or does not exist.");
                return;
            }
            if (selectedInputFile.length() % 2 != 0) {
                showError("Input file size is not a multiple of 2 bytes (expected 16-bit blocks).");
                return;
            }

            outputArea.append("Decrypting file: " + selectedInputFile.getName() + "\n");
            outputArea.append("Decrypted data (bytes as decimal):\n");

            List<Short> encryptedShorts = new ArrayList<>();
            try (FileInputStream fis = new FileInputStream(selectedInputFile);
                 DataInputStream dis = new DataInputStream(new BufferedInputStream(fis))) {
                while (dis.available() > 0) {
                    encryptedShorts.add(dis.readShort());
                }
            } catch (EOFException eof) {
                
            } catch (IOException e) {
                showError("Error reading encrypted input file: " + e.getMessage());
                e.printStackTrace();
                return;
            }

            if (encryptedShorts.isEmpty()) {
                showError("Encrypted input file is empty or could not be read.");
                return;
            }
            
            ByteArrayOutputStream decryptedByteStream = new ByteArrayOutputStream();
            StringBuilder decryptedTextOutput = new StringBuilder();

            for (int i = 0; i < encryptedShorts.size(); i++) {
                short encryptedShort = encryptedShorts.get(i);
                
                BigInteger c = BigInteger.valueOf(Short.toUnsignedInt(encryptedShort));
                BigInteger m = fastExponentialModular(c, d, n);
                
                if (m.compareTo(BigInteger.valueOf(255)) > 0) {
                    showError("Decryption error: Resulting value " + m + " is larger than a byte for block " + i);
                    return; 
                }
                byte decryptedByte = m.byteValue();
                decryptedByteStream.write(decryptedByte);

                
                decryptedTextOutput.append(Byte.toUnsignedInt(decryptedByte)); 
                if (i < encryptedShorts.size() - 1) {
                    decryptedTextOutput.append(" ");
                }
                if ((i + 1) % 10 == 0) { 
                    decryptedTextOutput.append("\n");
                }
            }
            outputArea.append(decryptedTextOutput.toString() + "\n\n");

            
            if (selectedOutputFile == null) {
                showError("Please choose an output file location.");
                return;
            }
            byte[] decryptedBytes = decryptedByteStream.toByteArray();
            boolean success = writeDecryptedFile(selectedOutputFile, decryptedBytes);
            if (success) {
                outputArea.append("Decryption successful.\nDecrypted data saved to: " + selectedOutputFile.getAbsolutePath());
                JOptionPane.showMessageDialog(this, "Decryption Complete!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                outputArea.append("Decryption failed. Could not write output file.");
            }


        } catch (NumberFormatException ex) {
            showError("Invalid number format for p, q, or d. Please enter valid integers.");
        } catch (Exception ex) {
            showError("An unexpected error occurred during decryption: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void showError(String message) {
        outputArea.append("ERROR: " + message + "\n");
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }


    private static BigInteger eulerFunction(BigInteger p, BigInteger q) {
        
        return p.subtract(ONE).multiply(q.subtract(ONE));
    }

    private static BigInteger[] euclid(BigInteger a, BigInteger b) {

        BigInteger[] result = new BigInteger[2];
        if (b.equals(ZERO)) {
            
            result[0] = ONE; 
            result[1] = a;   
            return result;
        }

        BigInteger x1 = ZERO, x2 = ONE;
        BigInteger y1 = ONE, y2 = ZERO;
        BigInteger temp_b = b; 

        while (b.compareTo(ZERO) > 0) {
            BigInteger quotient = a.divide(b);
            BigInteger remainder = a.mod(b); 

            BigInteger temp_x = x2.subtract(quotient.multiply(x1));
            BigInteger temp_y = y2.subtract(quotient.multiply(y1));

            a = b;
            b = remainder;

            x2 = x1;
            x1 = temp_x;

            y2 = y1;
            y1 = temp_y;
        }

        result[0] = x2; 
        result[1] = a;  
        return result;
    }

    private static BigInteger fastExponentialModular(BigInteger number, BigInteger exponent, BigInteger divider) {
        
        if (exponent.signum() < 0) {
            
            throw new IllegalArgumentException("Exponent cannot be negative for this implementation.");
        }
        if (divider.equals(ONE)) {
            return ZERO; 
        }

        BigInteger result = ONE;
        BigInteger base = number.mod(divider); 

        byte[] exponentBytes = exponent.toByteArray();

        for (int i = 0; i < exponent.bitLength(); i++) {
            if (exponent.testBit(i)) { 
                result = result.multiply(base).mod(divider);
            }
            
            base = base.multiply(base).mod(divider);
        }

        return result;
    }

    public static void main(String[] args) {
        
        SwingUtilities.invokeLater(() -> {
            RsaGui gui = new RsaGui();
            gui.setVisible(true);
        });
    }
}