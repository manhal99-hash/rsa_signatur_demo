package Krypto2;

import java.math.BigInteger;
import java.security.*; //Bibliothek für alles (keypair,keypair generator und für den ALgorithmusexception
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmusException;


public class RSA_Schluessel {
    public static void main(String[]args) throws NoSuchAlgorithmException { //Algorithmus Exception handeln

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); //hier verwenden vom java.Security package
        generator.initialize(3000); //schlüssellänge bestimmen
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate(); //private schlüssel extrahieren
        PublicKey publicKey = pair.getPublic(); //öffentlicher schlüssel extrahieren

        //casten zu RSA-Spezifischen Interfaces
        RSAPublicKey rsaPublic = (RSAPublicKey) publicKey;
        RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) privateKey;

        //Parameter der RSA-Algorithmus sind der öffentliche Exponent e, der
        //der öffentliche Modul n und der private Exponent d.


        //Alle Parameter holen
        BigInteger n = rsaPublic.getModulus();
        BigInteger e = rsaPublic.getPublicExponent();
        BigInteger d = rsaPrivate.getPrivateExponent();
        BigInteger p = rsaPrivate.getPrimeP();
        BigInteger q = rsaPrivate.getPrimeQ();
        BigInteger dP = rsaPrivate.getPrimeExponentP();
        BigInteger dQ = rsaPrivate.getPrimeExponentQ();
        BigInteger qInv = rsaPrivate.getCrtCoefficient();

        //Ausgabe aller Parametern
        System.out.println("Modul(n): "+n);
        System.out.println("Öffentlicher Exponent: "+e);
        System.out.println("Privater Exponent: "+d);
        System.out.println("Primzahl: "+p);
        System.out.println("Primzahl: "+q);
        System.out.println("d mod (p-1): "+dP);
        System.out.println("d mod (q-1): "+dQ);
        System.out.println("q^(-1) mod p (CRT Koeffezient): "+qInv);

        //1.2 RSA Universelle Fälschung

        //beliebige Nachricht s
        BigInteger s = new BigInteger("123456789");

        //x = s^e
        BigInteger x = s.modPow(e,n);

        //Verifizierer
        BigInteger verification = s.modPow(e,n);

        if(verification.equals(x)){
            System.out.println("Wahr, Signatur ist gültig.");
        } else{
            System.out.println("Falsch, Signatur ist ungültig.");
        }

    }
}
