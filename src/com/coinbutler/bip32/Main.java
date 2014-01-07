package com.coinbutler.bip32;

import com.google.bitcoin.core.*;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.store.BlockStoreException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Security;
import java.util.List;

public class Main {

    final static int ACCOUNT_BASE = 0x80000000;
    final static NetworkParameters params = TestNet3Params.get();

    public static void main(String[] args) throws IOException, ValidationException, AddressFormatException, BlockStoreException, JSONException, ScriptException, ProtocolException {


        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ECKey[] addresses = getECKeyAddresses(true);
        // mxpZPB3XzPTtfZFgCaCxecWo73nyDH8hDC
        final ECKey receivingKey = addresses[0];
        final Address receivingAddress = receivingKey.toAddress(params);

        System.out.println("Receiving Address: " + receivingAddress.toString());

        // mprGEhygxuXFQgvRC6PBToLFJ2uWByt1Ce
        final ECKey sendingKey = addresses[1];
        final Address sendingAddress = sendingKey.toAddress(params);

        System.out.println("Sending Address: " + sendingAddress.toString());


        // Start up a basic app using a class that automates some boilerplate. Ensure we always have at least one key.
        WalletAppKit kit = new WalletAppKit(params, new File("."), "test") {
            @Override
            protected void onSetupCompleted() {
                // This is called in a background thread after startAndWait is called, as setting up various objects
                // can do disk and network IO that may cause UI jank/stuttering in wallet apps if it were to be done
                // on the main thread.

                wallet().removeKey(receivingKey);
                wallet().removeKey(sendingKey);

                if (!wallet().hasKey(receivingKey)) {
                    wallet().addKey(receivingKey);
                }

                if (!wallet().hasKey(sendingKey)) {
                    wallet().addKey(sendingKey);
                }
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

        System.out.println("Ready! KeyChainSize: " + kit.wallet().getKeychainSize());
        System.out.println("Current Balance: " + Utils.bitcoinValueToFriendlyString(kit.wallet().getBalance()));

        Wallet.SendRequest request = Wallet.SendRequest.to(receivingAddress, Utils.toNanoCoins(0, 10));
        request.changeAddress = sendingAddress;
        try {
            boolean result = kit.wallet().completeTx(request);
            System.out.println(request.tx);
            //kit.peerGroup().broadcastTransaction(request.tx);
            if (!result) {
                System.out.println("Insufficient funds.");
            }

        } catch (KeyCrypterException e) {
            // We don't have the necessary private keys. This is expected. Let's initiate the offline procedure.
            System.out.println("We don't have the necessary private keys. This is expected. Let's initiate the offline procedure.");

            JSONObject obj = new JSONObject();
            JSONArray inputList = new JSONArray();

            Sha256Hash hash = null;
            List<TransactionInput> inputs = request.tx.getInputs();
            for (TransactionInput input : inputs) {
                JSONObject jsonInput = new JSONObject();
                hash = request.tx.hashForSignature(0, input.getOutpoint().getConnectedOutput().getScriptBytes(), Transaction.SigHash.ALL, false);
                jsonInput.put("sighash", hash);
                inputList.put(jsonInput);
            }
            obj.put("inputs", inputList);

            System.out.println(request.tx.toString());
            System.out.println(obj.toString());

            // NFC with offline device.
            String result = nfc(obj.toString());

            ECKey[] keys = getECKeyAddresses(false);
            ECKey privateSendingKey = keys[1];

            System.out.println(result);
            JSONObject signed = new JSONObject(result);
            JSONArray signedInputs = signed.getJSONArray("signedInputs");

            TransactionInput input = request.tx.getInput(0);

            JSONObject signatureParameters = signedInputs.getJSONObject(0);
            TransactionSignature offlineSignature = new TransactionSignature(new BigInteger(signatureParameters.getString("r")), new BigInteger(signatureParameters.getString("s")));
            input.setScriptSig(ScriptBuilder.createInputScript(offlineSignature, privateSendingKey));

            // TODO remove fixed fee
            request.fee = Utils.toNanoCoins("0.0001");
            System.out.println(request.tx);

            try {
                request.tx.verify();
                System.out.println("Verification is successful");
            } catch (VerificationException e1) {
                System.out.println("Verification is NOT successful");
                e1.printStackTrace();
            }
            kit.peerGroup().broadcastTransaction(request.tx);
        }

        System.out.println("DONE!!");


        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {}
    }

    private static String nfc(String rawData) throws JSONException, ProtocolException, ScriptException, UnsupportedEncodingException, ValidationException {
        // This takes place on an offline device
        // Communication will use nfc, bluetooth or qr codes.

        JSONObject data = new JSONObject(rawData);
        JSONObject result = new JSONObject();
        JSONArray resultInputs = new JSONArray();

        ECKey[] keys = getECKeyAddresses(false);
        ECKey sendingKey = keys[1];

        JSONArray inputs = data.getJSONArray("inputs");
        for (int i = 0; i < inputs.length(); i++) {
            JSONObject inputData = inputs.getJSONObject(i);

            Sha256Hash hash = new Sha256Hash(inputData.getString("sighash"));
            TransactionSignature signature = new TransactionSignature(sendingKey.sign(hash), Transaction.SigHash.ALL, false);
            JSONObject signatureParameters = new JSONObject();
            signatureParameters.put("r", signature.r.toString());
            signatureParameters.put("s", signature.s.toString());
            resultInputs.put(signatureParameters);
        }
        result.put("signedInputs", resultInputs);
        return result.toString();
    }

    private static ECKey[] getECKeyAddresses(boolean readonly) throws ValidationException, UnsupportedEncodingException {
        String secret = "0123456789012345678901234567890123456789012345678901234567891235";
        ExtendedKey extendedKey = ExtendedKey.create(secret.getBytes("UTF-8"));
        ExtendedKey accountM0 = extendedKey.getChild(ACCOUNT_BASE);
        ExtendedKey walletChainM01 = accountM0.getChild(0);

        ExtendedKey address1;
        ExtendedKey address2;
        if (readonly) {
            address1 = walletChainM01.getReadOnly().getChild(0);
            address2 = walletChainM01.getReadOnly().getChild(1);
        } else {
            address1 = walletChainM01.getChild(0);
            address2 = walletChainM01.getChild(1);
        }

        Key master1 = address1.getMaster();
        Key master2 = address2.getMaster();

        ECKey[] keys = {new ECKey(master1.getPrivate(), master1.getPublic()), new ECKey(master2.getPrivate(), master2.getPublic())};

        return keys;
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

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
