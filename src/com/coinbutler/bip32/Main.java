package com.coinbutler.bip32;

import com.google.bitcoin.core.*;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.store.BlockStoreException;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Security;

public class Main {

    final static int ACCOUNT_BASE = 0x80000000;
    final static NetworkParameters params = TestNet3Params.get();

    public static void main(String[] args) throws IOException, ValidationException, AddressFormatException, BlockStoreException {

        // mxpZPB3XzPTtfZFgCaCxecWo73nyDH8hDC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        final ECKey address = getECKeyAddress();


        // Start up a basic app using a class that automates some boilerplate. Ensure we always have at least one key.
        WalletAppKit kit = new WalletAppKit(params, new File("."), "test") {
            @Override
            protected void onSetupCompleted() {
                // This is called in a background thread after startAndWait is called, as setting up various objects
                // can do disk and network IO that may cause UI jank/stuttering in wallet apps if it were to be done
                // on the main thread.
                if (wallet().getKeychainSize() < 1)
                    wallet().addKey(address);
            }
        };

        // Download the block chain and wait until it's done.
        kit.startAndWait();

        // We want to know when we receive money.
        kit.wallet().addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet w, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
                //
                // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
                BigInteger value = tx.getValueSentToMe(w);
                System.out.println("Received tx for " + Utils.bitcoinValueToFriendlyString(value) + ": " + tx);
            }
        });


        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {}
        /*Address recipient = new Address(params, "12dJGBkCGc5QgJjg8osE11tkZjXxrMakqg");



        Transaction transaction = new Transaction(params);
        transaction.addOutput(Utils.toNanoCoins(0,20), recipient);
        transaction.addInput();

        System.out.println(transaction.toString());
       // Wallet.SendRequest request = Wallet.SendRequest.*/

        //runTestsPrivate();
    }

    private static ECKey getECKeyAddress() throws ValidationException, UnsupportedEncodingException {
        String secret = "0123456789012345678901234567890123456789012345678901234567891235";
        ExtendedKey extendedKey = ExtendedKey.create(secret.getBytes("UTF-8"));
        ExtendedKey accountM0 = extendedKey.getChild(ACCOUNT_BASE);
        ExtendedKey walletChainM01 = accountM0.getChild(0);
        ExtendedKey address = walletChainM01.getReadOnly().getChild(0);
        Key master = address.getMaster();
        return new ECKey(master.getPrivate(), master.getPublic());
    }

    private static void publicPrivateTest() throws UnsupportedEncodingException, ValidationException, AddressFormatException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String secret = "0123456789012345678901234567890123456789012345678901234567891235";
        ExtendedKey extendedKey = ExtendedKey.create(secret.getBytes("UTF-8"));
        System.out.println("Chain m: " + extendedKey.serialize(true));
        ExtendedKey accountM0 = extendedKey.getChild(ACCOUNT_BASE);
        if (!accountM0.isReadOnly()) {
            System.out.println("Chain m/0': " + accountM0.serialize(true));
        }

        ExtendedKey walletChainM01 = accountM0.getChild(0);
        if (!walletChainM01.isReadOnly()) {
            System.out.println("Chain m/0'/0: " + walletChainM01.serialize(true));
        }

        createAddresses(walletChainM01);
        // Now do the same with only the public key.
        createAddresses(walletChainM01.getReadOnly());



        ExtendedKey address = walletChainM01.getReadOnly().getChild(0);
        Key master = address.getMaster();
    }

    private static void createAddresses(ExtendedKey walletChain) throws ValidationException {

        for(int i = 0; i < 4; i++) {
            ExtendedKey address = walletChain.getChild(i);
            if (!address.isReadOnly()) {
                System.out.println("Chain m/0'/0/" + i + ": " + getPublicAddress(address) + " " + address.serialize(true));
            } else {
                System.out.println("Chain m/0'/0/" + i + ": " + getPublicAddress(address));
            }
        }
    }

    private static String getPublicAddress(ExtendedKey extendedKey) {
        Key master = extendedKey.getMaster();
        ECKey key = new ECKey(master.getPrivate(), master.getPublic());
        return key.toAddress(params).toString();
    }

    private static void runTestsPrivate() throws ValidationException {

        ExtendedKey extendedKey = ExtendedKey.create(hexStringToByteArray("000102030405060708090a0b0c0d0e0f"));

        System.out.println("Chain m: " + extendedKey.serialize(true));

        ExtendedKey accountM0 = extendedKey.getChild(ACCOUNT_BASE);
        System.out.println("Chain m/0': " + accountM0.serialize(true));

        ExtendedKey walletChainM01 = accountM0.getChild(1);
        System.out.println("Chain m/0'/1: " + walletChainM01.serialize(true));

        ExtendedKey accountM012 = walletChainM01.getChild(ACCOUNT_BASE + 2);
        System.out.println("Chain m/0'/1/2': " + accountM012.serialize(true));

        ExtendedKey walletChainM0122 = accountM012.getChild(2);
        System.out.println("Chain m/0'/1/2'/2: " + walletChainM0122.serialize(true));

        ExtendedKey walletChainM01221000000000 = walletChainM0122.getChild(1000000000);
        System.out.println("Chain m/0'/1/2'/2/1000000000: " + walletChainM01221000000000.serialize(true));
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
