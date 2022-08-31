package com.meizu.sysmonitor;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

public class ECDHUtils {

    public static void init(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PublicKey loadPublicKey(byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePublic(pubKey);
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        PrivateKey key;
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(1, data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePrivate(prvkey);
    }

    public static byte[] GetECDHKey(byte[] pubkey, byte[] prvkey) throws Exception{
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        PrivateKey prvk = loadPrivateKey(prvkey);
        PublicKey pubk = loadPublicKey(pubkey);
        ka.init(prvk);
        ka.doPhase(pubk, true);
        byte[] secret = ka.generateSecret();
        //System.out.println(name + bytesToHex(secret));
        return secret;
    }
}
