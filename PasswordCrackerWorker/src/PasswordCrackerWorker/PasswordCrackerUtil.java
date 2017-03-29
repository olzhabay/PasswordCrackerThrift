package PasswordCrackerWorker;

import org.apache.thrift.TException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static PasswordCrackerWorker.PasswordCrackerConts.PASSWORD_CHARS;
import static PasswordCrackerWorker.PasswordCrackerConts.PASSWORD_LEN;

public class PasswordCrackerUtil {

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot use MD5 Library:" + e.getMessage());
        }
    }

    private static String encrypt(String password, MessageDigest messageDigest) {
        messageDigest.update(password.getBytes());
        byte[] hashedValue = messageDigest.digest();
        return byteToHexString(hashedValue);
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                builder.append('0');
            }
            builder.append(hex);
        }
        return builder.toString();
    }

    /*
     * The findPasswordInRange method finds the password.
     * if it finds the password, it set the termination for transferring signal to master and returns password to caller.
     */
    public static String findPasswordInRange(long rangeBegin, long rangeEnd, String encryptedPassword, TerminationChecker terminationChecker) throws TException, InterruptedException {
        /** COMPLETE **/
        System.out.println("INFO: start " + rangeBegin + " " + rangeEnd);
        int[] passwordIterator = new int[PASSWORD_LEN];
        transformDecToBase36(rangeBegin, passwordIterator);
        for (long iterator = rangeBegin; iterator <= rangeEnd; iterator++) {
            if (terminationChecker.isTerminated()) return null;
            String password = transformIntToStr(passwordIterator);
            String hashedPassword = encrypt(password, getMessageDigest());
            if (hashedPassword.equals(encryptedPassword)) {
                terminationChecker.setTerminated();
                System.out.println("INFO: complete with success " + password);
                return password;
            }
            getNextCandidate(passwordIterator);
        }
        System.out.println("INFO: complete with no success");
        return null;
    }

    /* ###  transformDecToBase36  ###
     * The transformDecToBase36 transforms decimal into numArray that is base 36 number system
     * If you don't understand, refer to the homework01 overview
    */
    private static void transformDecToBase36(long numInDec, int[] numArrayInBase36) {
        /** COMPLETE **/
        for (int index = PASSWORD_LEN - 1; index >= 0; index--) {
            numArrayInBase36[index] = (int) (numInDec % 36);
            numInDec = numInDec / 36;
        }
    }

    //  ### getNextCandidate ###
    private static void getNextCandidate(int[] candidateChars) {
        /** OPTIONAL **/
        int reminder = 1;
        for (int index = PASSWORD_LEN - 1; index >= 0; index--) {
            candidateChars[index] += reminder;
            reminder = candidateChars[index] / 36;
            candidateChars[index] %= 36;
        }
    }

    private static String transformIntToStr(int[] chars) {
        char[] password = new char[chars.length];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_CHARS.charAt(chars[i]);
        }
        return new String(password);
    }
}
