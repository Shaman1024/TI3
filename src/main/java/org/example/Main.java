package org.example;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Scanner;
import java.util.stream.Stream;

//   1. Вычисление двух больших простых чисел +
//   2. Алгоритм Евклида
//   3. Расчёт публичной экспоненты
//   4. Расчёт приватной экспоненты
//   5. Формирование ключей
//   6. Текст в число
//   7. Шифрование
//   8. Дешифрование
public class Main {

    private static boolean isValid(BigInteger p, BigInteger q, BigInteger privateKey) {
        if (p.isProbablePrime(1) && q.isProbablePrime(1) && privateKey.isProbablePrime(1)) {
            return true;
        }
        return false;
    }

    private byte[] readFile(File file) {

        byte[] buffer = new byte[(int) file.length()];
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            fileInputStream.read(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    private void encrypt() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter p: ");
        BigInteger p = scanner.nextBigInteger();
        System.out.print("Enter q: ");
        BigInteger q = scanner.nextBigInteger();
        System.out.print("Enter private key: ");
        BigInteger privateKey = scanner.nextBigInteger();

        if (!isValid(p, q, privateKey)) {
            return;
        }

        BigInteger publicKey = Euclid(privateKey, EulerFunction(p, q)).mod(EulerFunction(p, q));
        System.out.print("public key = " + publicKey + "\n");



    }

    private static BigInteger EulerFunction(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    private static BigInteger Euclid(BigInteger e, BigInteger euler) {

        BigInteger reminder = BigInteger.ZERO;
        BigInteger quotient = BigInteger.ONE;

        BigInteger x_prev = BigInteger.ONE;
        BigInteger y_prev = BigInteger.ZERO;

        BigInteger x_curr = BigInteger.ZERO;
        BigInteger y_curr = BigInteger.ONE;

        BigInteger x_next = BigInteger.ONE;
        BigInteger y_next = BigInteger.ONE;

        while (!reminder.equals(BigInteger.ONE)) {
            reminder = euler.mod(e);
            quotient = euler.divide(e);

            euler = e;
            e = reminder;

            x_next = x_prev.subtract(quotient.multiply(x_curr));
            x_prev = x_curr;
            x_curr = x_next;

            y_next = y_prev.subtract(quotient.multiply(y_curr));
            y_prev = y_curr;
            y_curr = y_next;

        }
        return x_curr;
    }

    public static void main(String[] args) {

    }
}