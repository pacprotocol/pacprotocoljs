/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

'use strict';

//const LoadBLS = require('@liutianv1/bls-signatures');
//const crypto = require('crypto');
//
///*
//#ifndef BUILD_BITCOIN_INTERNAL
//void CBLSSecretKey::MakeNewKey()
//{
//    unsigned char buf[32];
//    while (true) {
//        GetStrongRandBytes(buf, sizeof(buf));
//        try {
//            impl = bls::PrivateKey::FromBytes(bls::Bytes((const uint8_t*)buf, SerSize));
//            break;
//        } catch (...) {
//        }
//    }
//    fValid = true;
//    cachedHash.SetNull();
//}
//
//*/
//
//const axios = require('axios');
//
//const bls_fromsecret = (secret_key) => {
//    return new Promise((resolve) => {
//        const data = {
//            jsonrpc: "2.0",
//            method: "bls",
//            params: ['fromsecret', secret_key],
//            id: 0,
//        }
//        axios.post("http://user:pass@localhost:7222", data).then((res) => {
//            resolve(res.data.result);
//        })
//    })
//}
//
//(async () => {
//    const BLS = await LoadBLS();
//    let secret_key = "";
//    let public_key = "";
//
//    while (true) {
//        let seed = null;
//        let sk = null;
//        let pk = null;
//        try {
//            seed = crypto.randomBytes(32);
//            const sk = BLS.PrivateKey.from_bytes(seed, true);
//            const pk = sk.get_g1();
//            secret_key = Buffer.from(sk.serialize()).toString("hex")
//            public_key = Buffer.from(pk.serialize()).toString("hex")
//            sk.delete();
//            pk.delete();
//            
//            if (["0", "1", "2", "3", "4", "5", "6", "7", "c", "d", "e", "f"].includes(public_key[0])) {
//                break;
//            }
//            let first_char_replace = null;
//            switch (public_key[0]) {
//                case "8": first_char_replace = "0"; break;
//                case "9": first_char_replace = "1"; break;
//                case "a": first_char_replace = "8"; break;
//                case "b": first_char_replace = "9"; break;
//            }
//            public_key = first_char_replace + public_key.substring(1)
//
//            const res = await bls_fromsecret(secret_key);
//            if (res.secret == secret_key && res.public == public_key) {
//                console.log("Works!");
//            } else {
//                console.log("-------------------------------------------------------------------------")
//                console.log("PUBLIC KEY IS WRONG???", "should", secret_key, "is", res.secret);
//                console.log("Private key", secret_key, "Public key", public_key);
//                console.log("Axios Private key", res.secret, "Public key", res.public);
//                console.log("-------------------------------------------------------------------------")
//            }
//        } catch (e) {
//            console.log("----------------------------------");
//            console.log("CRASH", e);
//            console.log("----------------------------------");
//        }
//    }
//    console.log("bls fromsecret " + secret_key);
//    console.log("RES:", public_key);
//})()

///////////////////////////////////////////////////////////////////////////////////////////////

'use strict';

const bls = require('noble-bls12-381');
const crypto = require('crypto');

const bytesToNumberBE = (bytes) => {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}

const isWithinCurveOrder = (num) => {
    return 0 < num && num < 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
}

const randomBytesSeed = (length, seed, options = {base_seed: "HHd8be7STFd8pnM9Fh4S"}) => {
	if (typeof length !== 'number' || !Number.isInteger(length) || length < 1) {
		throw new TypeError(
			'`length` argument must be a valid strictly positive integer.',
		);
	}

	if (!seed) {
		return randomBytes(length);
	}
	let round = crypto.createHash('sha256')
		.update(options.base_seed)
		.update(seed)
		.digest();
	let output = Buffer.alloc(0);

	while (output.length < length) {
		round = crypto.createHash('sha256').update(round).digest();
		output = Buffer.concat([output, round]);
	}

	return output.slice(0, length);
}

const randomPrivateKey = (random_bytes) => {
    let i = 0;
    if (!random_bytes) {
        random_bytes = crypto.randomBytes(32);
    }
    while (true) {
        const b32 = randomBytesSeed(32, random_bytes + i.toString());
        const num = bytesToNumberBE(b32);
        if (isWithinCurveOrder(num) && num !== 1n) {
            return b32;
        }
        if (i > 10000) {
            throw new Error("Could not generate a valid private key");
        }
        i++;
    }
}

(async () => {
    let secret_key = "";
    let public_key = "";
    const bls_amount = 10;
    for (let i = 0; i < bls_amount; i++){
        try {
            const sk = randomPrivateKey();
            const pk = bls.getPublicKey(sk);
            secret_key = Buffer.from(sk).toString("hex")
            public_key = Buffer.from(pk).toString("hex")

            let first_char_replace = null;
            switch (public_key[0]) {
                case "8": first_char_replace = "0"; break;
                case "9": first_char_replace = "1"; break;
                case "a": first_char_replace = "8"; break;
                case "b": first_char_replace = "9"; break;
            }
            public_key = first_char_replace + public_key.substring(1);
            console.log((i+1) + ".Private key:", secret_key, "Public key:", public_key);
        } catch (e) {
            console.log("CRASH", e);
        }
    }
})()

