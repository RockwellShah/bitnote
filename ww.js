let ww_version = "01";
self.addEventListener("message", handleMessage);
let eh = new ww_encryption_handler();
let active_mp_buff = null;
let active_pk_buff = null;
let active_ecdh_priv_buff = null;
let secp_h;
let salt_byte_len = 12;
let salt_hex_len = 24;
function handleMessage(msg_event) {
    var msg_type = msg_event.data.msg_type;
    switch (msg_type) {
    case "get_version":
        self.postMessage(ww_version);
        break;
    case "ecdh_enc":
        var ecdh_pk_buff = (checkForProperty(msg_event.data.ecdh_pk_buff)) ? msg_event.data.ecdh_pk_buff : active_ecdh_priv_buff;
        newEcdhEncrypt(msg_event.data.msg_buff, msg_event.data.ecdh_pub, msg_event.data.aad, ecdh_pk_buff, function(encrypted_buff, salt_buff) {
            self.postMessage({
                encrypted_buff: encrypted_buff,
                salt_buff: salt_buff
            }, [encrypted_buff, salt_buff]);
        });
        break;
    case "ecdh_de":
        var ecdh_pk_buff = (checkForProperty(msg_event.data.ecdh_pk_buff)) ? msg_event.data.ecdh_pk_buff : active_ecdh_priv_buff;
        newEcdhDecrypt(msg_event.data.msg_buff, msg_event.data.ecdh_pub, msg_event.data.aad, ecdh_pk_buff, function(decrypted_buff) {
            if (decrypted_buff != null)
                self.postMessage({
                    decrypted_buff: decrypted_buff
                }, [decrypted_buff]);
            else
                self.postMessage(null);
        });
        break;
    case "bio_enc":
        eh.newMsgDefaultEncrypt(msg_event.data.msg_buff, msg_event.data.key_buff, function(salt_buff, encrypted_buff) {
            self.postMessage({
                salt_buff: salt_buff,
                encrypted_buff: encrypted_buff
            }, [salt_buff, encrypted_buff]);
        });
        break;
    case "bio_de":
        iterations = 1000000;
        decryptPrep(msg_event.data.cipher_buff, msg_event.data.key_buff, msg_event.data.salt_buff, iterations, decryptPost);
        break;
    case "de":
        var mp_buff = (checkForProperty(msg_event.data.mp_buff)) ? msg_event.data.mp_buff : active_mp_buff;
        iterations = 1000000;
        decryptPrep(msg_event.data.cipher_buff, mp_buff, msg_event.data.salt_buff, iterations, decryptPost);
        break;
    case "set_mp":
        active_mp_buff = msg_event.data.key_buff;
        self.postMessage(true);
        break;
    case "sign_stuff":
        if (active_pk_buff != null)
            signStuff(msg_event.data.msg_buff);
        else
            self.postMessage(null);
        break;
    case "gen_ac":
        generateNewAccount();
        break;
    case "unlock_ac":
        iterations = 1000000;
        var decrypt_obj_array = [{
            data_buff: msg_event.data.cipher_buff,
            mp_buff: active_mp_buff,
            salt_buff: msg_event.data.salt_buff
        }, {
            data_buff: msg_event.data.ecdh_buff,
            mp_buff: active_mp_buff,
            salt_buff: msg_event.data.ecdh_salt_buff
        }, ];
        multiDecrypt(decrypt_obj_array, iterations, function(decrypted) {
            if (decrypted.length == 2 && (decrypted[0] != null && decrypted[1] != null)) {
                active_pk_buff = decrypted[0];
                active_ecdh_priv_buff = decrypted[1];
                self.postMessage(true);
            } else
                self.postMessage(false);
        });
        break;
    case "remove_keys":
        active_mp_buff = null;
        active_pk_buff = null;
        active_ecdh_priv_buff = null;
        self.postMessage(true);
        break;
    case "check_mp":
        self.postMessage((active_mp_buff == null) ? false : true);
        break;
    case "check_pk":
        self.postMessage((active_pk_buff == null) ? false : true);
        break;
    case "check_both":
        self.postMessage((active_pk_buff != null && active_mp_buff != null) ? true : false);
        break;
    case "new_key_pair":
        var new_keys = getNewKeyPairBuffs();
        self.postMessage({
            pk_buff: new_keys.pk_buff,
            pub_buff: new_keys.pub_buff
        }, [new_keys.pk_buff, new_keys.pub_buff]);
        break;
    case "encrypt_mp":
        eh.hkdfEncrypt(active_mp_buff.slice(), msg_event.data.key_buff, function(salt_buff, encrypted_buff) {
            self.postMessage({
                salt_buff: salt_buff,
                encrypted_buff: encrypted_buff
            }, [salt_buff, encrypted_buff]);
        });
        break;
    case "decrypt_mp":
        eh.hkdfDecrypt(msg_event.data.msg_buff, msg_event.data.key_buff, decryptPost);
        break;
    }
    function signStuff(msg_buff) {
        msg_buff = new Uint8Array(msg_buff);
        var temp_pk = new Uint8Array(active_pk_buff);
        const pub = secp_h.getPublicKey(temp_pk);
        var signature = secp_h.sign(msg_buff, temp_pk, {
            lowS: true,
            extraEntropy: true
        });
        console.log(secp_h.verify(signature, msg_buff, pub));
        var r_buff = bigToPaddedHex(signature.r);
        var s_buff = bigToPaddedHex(signature.s);
        r_buff = hexToArrayBuffer(r_buff, Uint8Array).buffer;
        s_buff = hexToArrayBuffer(s_buff, Uint8Array).buffer;
        self.postMessage({
            r: r_buff,
            s: s_buff,
            recovery: signature.recovery
        }, [r_buff, s_buff]);
    }
    function newEcdhEncrypt(msg_buff, ecdh_pub, aad="", ecdh_pk_buff, callback) {
        eh.importEcdhKey(ecdh_pk_buff, "privateKey", "deriveKey", "pkcs8", function(imported_priv) {
            eh.importEcdhKey(ecdh_pub, "publicKey", null, "raw", function(imported_public) {
                eh.deriveEcdhKey(imported_priv, imported_public, function(derived_key) {
                    var iv = self.crypto.getRandomValues(new Uint8Array(salt_byte_len));
                    eh.encrypt(derived_key, msg_buff, iv, function(encrypted_buff) {
                        callback(encrypted_buff, iv.buffer);
                    }, aad);
                });
            })
        });
    }
    function newEcdhDecrypt(msg_buff, ecdh_pub, aad="", ecdh_pk_buff, callback) {
        eh.importEcdhKey(ecdh_pk_buff, "privateKey", "deriveKey", "pkcs8", function(imported_priv) {
            eh.importEcdhKey(ecdh_pub, "publicKey", null, "raw", function(imported_public) {
                eh.deriveEcdhKey(imported_priv, imported_public, function(derived_key) {
                    var iv = msg_buff.slice(0, salt_byte_len);
                    msg_buff = msg_buff.slice(salt_byte_len);
                    eh.noDecodeDecrypt(derived_key, msg_buff, iv, function(decrypted_buff) {
                        callback(decrypted_buff);
                    }, aad);
                });
            })
        });
    }
    function getNewKeyPairBuffs() {
        var pk_buff = secp_h.utils.randomPrivateKey();
        var pub_buff = secp_h.getPublicKey(pk_buff, false).buffer;
        pk_buff = pk_buff.buffer;
        return {
            pk_buff,
            pub_buff
        };
    }
    function generateNewAccount() {
        var new_keys = getNewKeyPairBuffs();
        var pk_buff = new_keys.pk_buff;
        var pub_buff = new_keys.pub_buff;
        eh.generateECDHKeys(function(ecdh_keys) {
            active_pk_buff = pk_buff;
            exportEcdhKeys(ecdh_keys, function(exported_priv, exported_pub) {
                active_ecdh_priv_buff = exported_priv;
                var enc_obj_array = [{
                    data: active_pk_buff,
                    mp_buff: active_mp_buff
                }, {
                    data: exported_priv,
                    mp_buff: active_mp_buff
                }, ];
                multiEncrypt(enc_obj_array, function(encrypted_array) {
                    var qq = 22;
                    self.postMessage({
                        pub_buff: pub_buff,
                        salt_buff: encrypted_array[0].salt_buff,
                        encrypted_buff: encrypted_array[0].encrypted_buff,
                        ecdh_priv_buff: encrypted_array[1].encrypted_buff,
                        ecdh_salt_buff: encrypted_array[1].salt_buff,
                        ecdh_pub_buff: exported_pub,
                    }, [pub_buff, encrypted_array[0].salt_buff, encrypted_array[0].encrypted_buff, encrypted_array[1].encrypted_buff, encrypted_array[1].salt_buff, exported_pub]);
                });
            });
        });
    }
    function exportEcdhKeys(keys, callback) {
        eh.exportKey(keys.privateKey, "pkcs8", function(exported_priv) {
            eh.exportKey(keys.publicKey, "raw", function(exported_public) {
                callback(exported_priv, exported_public);
            });
        });
    }
    function multiEncrypt(enc_obj_array, callback) {
        let end_point = enc_obj_array.length;
        let start_point = 0;
        let encrypted_array = [];
        (function encrypt_next(pointer) {
            if (pointer < end_point) {
                eh.newMsgDefaultEncrypt(enc_obj_array[pointer].data, enc_obj_array[pointer].mp_buff, function(salt_buff, encrypted_buff) {
                    encrypted_array.push({
                        salt_buff: salt_buff,
                        encrypted_buff: encrypted_buff
                    });
                    encrypt_next(++pointer);
                });
            } else
                callback(encrypted_array);
        }
        )(start_point);
    }
    function multiDecrypt(decrypt_obj_array, iterations, callback) {
        let end_point = decrypt_obj_array.length;
        let start_point = 0;
        let decrypted_array = [];
        (function decrypt_next(pointer) {
            if (pointer < end_point) {
                eh.defaultDeriveKey(decrypt_obj_array[pointer].mp_buff, iterations, decrypt_obj_array[pointer].salt_buff, function(key) {
                    eh.noDecodeDecrypt(key, decrypt_obj_array[pointer].data_buff, decrypt_obj_array[pointer].salt_buff, function(decrpyted_stuff) {
                        decrypted_array.push(decrpyted_stuff);
                        decrypt_next(++pointer);
                    });
                });
            } else
                callback(decrypted_array);
        }
        )(start_point);
    }
    function decryptPrep(cipher_buff, phrase_buff, salt_buff, iterations, cb) {
        eh.defaultDeriveKey(phrase_buff, iterations, salt_buff, function(key) {
            eh.noDecodeDecrypt(key, cipher_buff, salt_buff, cb);
        });
    }
    function decryptPost(decrypted) {
        if (decrypted != null)
            self.postMessage(decrypted, [decrypted]);
        else
            self.postMessage(null);
    }
    function checkForProperty(prop) {
        return (prop === "" || prop === null || prop === undefined) ? false : true;
    }
}
function hexToArrayBuffer(hex_str, buffer_type=null) {
    const regex = new RegExp(/0x/i);
    if (regex.test(hex_str.substring(0, 2)))
        hex_str = hexStringToHexNumber(hex_str);
    var ret = [];
    for (var i = 0; i < hex_str.length / 2; i++) {
        var x = i * 2;
        const n = parseInt(hex_str.substr(x, 2), 16);
        ret.push(n);
    }
    if (buffer_type)
        return new buffer_type(ret);
    else
        return ret;
}
function bigToPaddedHex(bigi) {
    var hex = bigi.toString(16);
    return hex.padStart(32 * 2, '0');
}
function ww_encryption_handler() {
    this.newMsgDefaultEncrypt = newMsgDefaultEncrypt;
    function newMsgDefaultEncrypt(plaintext_buffer, phrase_buffer, cb) {
        var salt = self.crypto.getRandomValues(new Uint8Array(salt_byte_len));
        phrase_buffer = new Uint8Array(phrase_buffer);
        plaintext_buffer = new Uint8Array(plaintext_buffer);
        defaultDeriveKey(phrase_buffer, 1000000, salt, function(key) {
            encrypt(key, plaintext_buffer, salt, function(encrpyted_stuff) {
                cb(salt.buffer, encrpyted_stuff);
            });
        });
    }
    this.hkdfEncrypt = hkdfEncrypt;
    function hkdfEncrypt(plaintext_buffer, phrase_buffer, cb) {
        var salt = self.crypto.getRandomValues(new Uint8Array(salt_byte_len));
        phrase_buffer = new Uint8Array(phrase_buffer);
        plaintext_buffer = new Uint8Array(plaintext_buffer);
        hkdfDeriveKey(phrase_buffer, salt, function(key) {
            encrypt(key, plaintext_buffer, salt, function(encrpyted_stuff) {
                cb(salt.buffer, encrpyted_stuff);
            });
        });
    }
    this.hkdfDecrypt = hkdfDecrypt;
    function hkdfDecrypt(cipher_buff, phrase_buffer, cb) {
        phrase_buffer = new Uint8Array(phrase_buffer);
        cipher_buff = new Uint8Array(cipher_buff);
        var salt = cipher_buff.slice(0, salt_byte_len);
        cipher_buff = cipher_buff.slice(salt_byte_len);
        hkdfDeriveKey(phrase_buffer, salt, function(key) {
            noDecodeDecrypt(key, cipher_buff, salt, function(decrypted_buff) {
                cb(decrypted_buff);
            });
        });
    }
    this.encrypt = encrypt;
    function encrypt(key, plaintext, iv, cb, aad="") {
        var alg_obj = {
            name: "AES-GCM",
            iv
        };
        if (aad != "")
            alg_obj.additionalData = aad;
        self.crypto.subtle.encrypt(alg_obj, key, plaintext).then((encrpyted_stuff)=>{
            cb(encrpyted_stuff);
        }
        );
    }
    this.noDecodeDecrypt = noDecodeDecrypt;
    function noDecodeDecrypt(key, ciphertext, iv, cb, aad="") {
        var alg_obj = {
            name: "AES-GCM",
            iv
        };
        if (aad != "")
            alg_obj.additionalData = aad;
        self.crypto.subtle.decrypt(alg_obj, key, ciphertext).then((decrpyted_stuff)=>{
            cb(decrpyted_stuff);
        }
        ).catch(function(e) {
            cb(null)
        });
    }
    this.defaultDeriveKey = defaultDeriveKey;
    function defaultDeriveKey(encoded_material, iterations, salt, cb) {
        var alg_obj = {
            name: "PBKDF2",
            salt,
            iterations: iterations,
            hash: "SHA-512",
        };
        var derived_for_alg = {
            "name": "AES-GCM",
            "length": 256
        };
        self.crypto.subtle.importKey("raw", encoded_material, alg_obj.name, false, ["deriveBits", "deriveKey"]).then((key_mat)=>{
            self.crypto.subtle.deriveKey(alg_obj, key_mat, derived_for_alg, true, ["encrypt", "decrypt"]).then((key)=>{
                cb(key);
            }
            );
        }
        );
    }
    this.hkdfDeriveKey = hkdfDeriveKey;
    function hkdfDeriveKey(encoded_material, salt, cb) {
        var alg_obj = {
            name: "HKDF",
            salt,
            hash: "SHA-512",
            info: new ArrayBuffer(0),
        };
        var derived_for_alg = {
            "name": "AES-GCM",
            "length": 256
        };
        self.crypto.subtle.importKey("raw", encoded_material, alg_obj.name, false, ["deriveBits", "deriveKey"]).then((key_mat)=>{
            self.crypto.subtle.deriveKey(alg_obj, key_mat, derived_for_alg, true, ["encrypt", "decrypt"]).then((key)=>{
                cb(key);
            }
            );
        }
        );
    }
    this.defaultGenerateSalt = defaultGenerateSalt;
    function defaultGenerateSalt(size) {
        var hb = [];
        var ns = "";
        for (var i = 48; i <= 122; i++)
            if (i < 58 || i > 97)
                hb.push(String.fromCodePoint(i));
        for (var i = 0; i < size; i++)
            ns += hb[getRandomInclusive(0, (hb.length - 1))];
        return ns;
    }
    this.hexToArrayBuffer = hexToArrayBuffer;
    function hexToArrayBuffer(hex_str, buffer_type=null) {
        const regex = new RegExp(/0x/i);
        if (regex.test(hex_str.substring(0, 2)))
            hex_str = hex_str.substring(2);
        var ret = [];
        for (var i = 0; i < hex_str.length / 2; i++) {
            var x = i * 2;
            const n = parseInt(hex_str.substr(x, 2), 16);
            ret.push(n);
        }
        if (buffer_type)
            return new buffer_type(ret);
        else
            return ret;
    }
    function getRandomInclusive(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    this.generateECDHKeys = generateECDHKeys;
    function generateECDHKeys(callback) {
        self.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-521",
        }, true, ["deriveKey"]).then(callback);
    }
    this.importEcdhKey = importEcdhKey;
    function importEcdhKey(keyData, keyType, usage, keyFormat, callback) {
        self.crypto.subtle.importKey(keyFormat, keyData, {
            name: "ECDH",
            namedCurve: "P-521",
        }, keyType !== "privateKey", usage ? [usage] : []).then(callback);
    }
    this.exportKey = exportKey;
    function exportKey(key, keyFormat, callback) {
        self.crypto.subtle.exportKey(keyFormat, key).then(callback);
    }
    this.deriveEcdhKey = deriveEcdhKey;
    function deriveEcdhKey(privateKey, publicKey, callback) {
        self.crypto.subtle.deriveKey({
            name: "ECDH",
            public: publicKey,
        }, privateKey, {
            name: "AES-GCM",
            length: 256,
        }, true, ["encrypt", "decrypt"]).then(callback);
    }
    function preEncoder(input_msg) {
        var text_encoder = new TextEncoder();
        if (/^base64_/i.test(input_msg)) {
            try {
                input_msg = input_msg.replace("base64_", "");
                var tc = atob(input_msg);
                return strToUint8(tc);
            } catch (e) {
                return text_encoder.encode(input_msg);
            }
        } else
            return text_encoder.encode(input_msg);
    }
}
function getRandomInclusive(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function bufferToHex(buffer) {
    return [...new Uint8Array(buffer)].map(b=>b.toString(16).padStart(2, "0")).join("");
}
function set_secp256k1(secp256k1) {
    secp_h = secp256k1;
}
function set_pbkdf2(pbkdf2, sha512, pbkdf2Async) {}
(()=>{
    "use strict";
    var t = {
        d: (e,n)=>{
            for (var r in n)
                t.o(n, r) && !t.o(e, r) && Object.defineProperty(e, r, {
                    enumerable: !0,
                    get: n[r]
                })
        }
        ,
        o: (t,e)=>Object.prototype.hasOwnProperty.call(t, e),
        r: t=>{
            "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(t, Symbol.toStringTag, {
                value: "Module"
            }),
            Object.defineProperty(t, "__esModule", {
                value: !0
            })
        }
    }
      , e = {};
    function n(t) {
        if (!Number.isSafeInteger(t) || t < 0)
            throw new Error(`Wrong positive integer: ${t}`)
    }
    function r(t, ...e) {
        if (!(t instanceof Uint8Array))
            throw new TypeError("Expected Uint8Array");
        if (e.length > 0 && !e.includes(t.length))
            throw new TypeError(`Expected Uint8Array of length ${e}, not of length=${t.length}`)
    }
    t.r(e),
    t.d(e, {
        bitGet: ()=>Z,
        bitLen: ()=>_,
        bitMask: ()=>j,
        bitSet: ()=>V,
        bytesToHex: ()=>L,
        bytesToNumberBE: ()=>T,
        bytesToNumberLE: ()=>q,
        concatBytes: ()=>k,
        createHmacDrbg: ()=>K,
        ensureBytes: ()=>C,
        equalBytes: ()=>P,
        hexToBytes: ()=>R,
        hexToNumber: ()=>H,
        numberToBytesBE: ()=>N,
        numberToBytesLE: ()=>D,
        numberToHexUnpadded: ()=>U,
        numberToVarBytesBE: ()=>F,
        utf8ToBytes: ()=>$,
        validateObject: ()=>W
    });
    const i = {
        number: n,
        bool: function(t) {
            if ("boolean" != typeof t)
                throw new Error(`Expected boolean, not ${t}`)
        },
        bytes: r,
        hash: function(t) {
            if ("function" != typeof t || "function" != typeof t.create)
                throw new Error("Hash should be wrapped by utils.wrapConstructor");
            n(t.outputLen),
            n(t.blockLen)
        },
        exists: function(t, e=!0) {
            if (t.destroyed)
                throw new Error("Hash instance has been destroyed");
            if (e && t.finished)
                throw new Error("Hash#digest() has already been called")
        },
        output: function(t, e) {
            r(t);
            const n = e.outputLen;
            if (t.length < n)
                throw new Error(`digestInto() expects output buffer of length at least ${n}`)
        }
    }
      , o = {
        node: void 0,
        web: "object" == typeof self && "crypto"in self ? self.crypto : void 0
    }
      , s = t=>new DataView(t.buffer,t.byteOffset,t.byteLength)
      , f = (t,e)=>t << 32 - e | t >>> e;
    if (68 !== new Uint8Array(new Uint32Array([287454020]).buffer)[0])
        throw new Error("Non little-endian hardware is not supported");
    Array.from({
        length: 256
    }, ((t,e)=>e.toString(16).padStart(2, "0")));
    const a = async()=>{}
    ;
    async function c(t, e, n) {
        let r = Date.now();
        for (let i = 0; i < t; i++) {
            n(i);
            const t = Date.now() - r;
            t >= 0 && t < e || (await a(),
            r += t)
        }
    }
    function h(t) {
        if ("string" == typeof t && (t = function(t) {
            if ("string" != typeof t)
                throw new TypeError("utf8ToBytes expected string, got " + typeof t);
            return (new TextEncoder).encode(t)
        }(t)),
        !(t instanceof Uint8Array))
            throw new TypeError(`Expected input type is Uint8Array (got ${typeof t})`);
        return t
    }
    class u {
        clone() {
            return this._cloneInto()
        }
    }
    const l = t=>"[object Object]" === Object.prototype.toString.call(t) && t.constructor === Object;
    function d(t) {
        const e = e=>t().update(h(e)).digest()
          , n = t();
        return e.outputLen = n.outputLen,
        e.blockLen = n.blockLen,
        e.create = ()=>t(),
        e
    }
    function b(t=32) {
        if (o.web)
            return o.web.getRandomValues(new Uint8Array(t));
        if (o.node)
            return new Uint8Array(o.node.randomBytes(t).buffer);
        throw new Error("The environment doesn't have randomBytes function")
    }
    class p extends u {
        constructor(t, e, n, r) {
            super(),
            this.blockLen = t,
            this.outputLen = e,
            this.padOffset = n,
            this.isLE = r,
            this.finished = !1,
            this.length = 0,
            this.pos = 0,
            this.destroyed = !1,
            this.buffer = new Uint8Array(t),
            this.view = s(this.buffer)
        }
        update(t) {
            i.exists(this);
            const {view: e, buffer: n, blockLen: r} = this
              , o = (t = h(t)).length;
            for (let i = 0; i < o; ) {
                const f = Math.min(r - this.pos, o - i);
                if (f !== r)
                    n.set(t.subarray(i, i + f), this.pos),
                    this.pos += f,
                    i += f,
                    this.pos === r && (this.process(e, 0),
                    this.pos = 0);
                else {
                    const e = s(t);
                    for (; r <= o - i; i += r)
                        this.process(e, i)
                }
            }
            return this.length += t.length,
            this.roundClean(),
            this
        }
        digestInto(t) {
            i.exists(this),
            i.output(t, this),
            this.finished = !0;
            const {buffer: e, view: n, blockLen: r, isLE: o} = this;
            let {pos: f} = this;
            e[f++] = 128,
            this.buffer.subarray(f).fill(0),
            this.padOffset > r - f && (this.process(n, 0),
            f = 0);
            for (let t = f; t < r; t++)
                e[t] = 0;
            !function(t, e, n, r) {
                if ("function" == typeof t.setBigUint64)
                    return t.setBigUint64(e, n, r);
                const i = BigInt(32)
                  , o = BigInt(4294967295)
                  , s = Number(n >> i & o)
                  , f = Number(n & o)
                  , a = r ? 4 : 0
                  , c = r ? 0 : 4;
                t.setUint32(e + a, s, r),
                t.setUint32(e + c, f, r)
            }(n, r - 8, BigInt(8 * this.length), o),
            this.process(n, 0);
            const a = s(t)
              , c = this.outputLen;
            if (c % 4)
                throw new Error("_sha2: outputLen should be aligned to 32bit");
            const h = c / 4
              , u = this.get();
            if (h > u.length)
                throw new Error("_sha2: outputLen bigger than state");
            for (let t = 0; t < h; t++)
                a.setUint32(4 * t, u[t], o)
        }
        digest() {
            const {buffer: t, outputLen: e} = this;
            this.digestInto(t);
            const n = t.slice(0, e);
            return this.destroy(),
            n
        }
        _cloneInto(t) {
            t || (t = new this.constructor),
            t.set(...this.get());
            const {blockLen: e, buffer: n, length: r, finished: i, destroyed: o, pos: s} = this;
            return t.length = r,
            t.pos = s,
            t.finished = i,
            t.destroyed = o,
            r % e && t.buffer.set(n),
            t
        }
    }
    const w = (t,e,n)=>t & e ^ t & n ^ e & n
      , g = new Uint32Array([1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298])
      , y = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225])
      , m = new Uint32Array(64);
    class E extends p {
        constructor() {
            super(64, 32, 8, !1),
            this.A = 0 | y[0],
            this.B = 0 | y[1],
            this.C = 0 | y[2],
            this.D = 0 | y[3],
            this.E = 0 | y[4],
            this.F = 0 | y[5],
            this.G = 0 | y[6],
            this.H = 0 | y[7]
        }
        get() {
            const {A: t, B: e, C: n, D: r, E: i, F: o, G: s, H: f} = this;
            return [t, e, n, r, i, o, s, f]
        }
        set(t, e, n, r, i, o, s, f) {
            this.A = 0 | t,
            this.B = 0 | e,
            this.C = 0 | n,
            this.D = 0 | r,
            this.E = 0 | i,
            this.F = 0 | o,
            this.G = 0 | s,
            this.H = 0 | f
        }
        process(t, e) {
            for (let n = 0; n < 16; n++,
            e += 4)
                m[n] = t.getUint32(e, !1);
            for (let t = 16; t < 64; t++) {
                const e = m[t - 15]
                  , n = m[t - 2]
                  , r = f(e, 7) ^ f(e, 18) ^ e >>> 3
                  , i = f(n, 17) ^ f(n, 19) ^ n >>> 10;
                m[t] = i + m[t - 7] + r + m[t - 16] | 0
            }
            let {A: n, B: r, C: i, D: o, E: s, F: a, G: c, H: h} = this;
            for (let t = 0; t < 64; t++) {
                const e = h + (f(s, 6) ^ f(s, 11) ^ f(s, 25)) + ((u = s) & a ^ ~u & c) + g[t] + m[t] | 0
                  , l = (f(n, 2) ^ f(n, 13) ^ f(n, 22)) + w(n, r, i) | 0;
                h = c,
                c = a,
                a = s,
                s = o + e | 0,
                o = i,
                i = r,
                r = n,
                n = e + l | 0
            }
            var u;
            n = n + this.A | 0,
            r = r + this.B | 0,
            i = i + this.C | 0,
            o = o + this.D | 0,
            s = s + this.E | 0,
            a = a + this.F | 0,
            c = c + this.G | 0,
            h = h + this.H | 0,
            this.set(n, r, i, o, s, a, c, h)
        }
        roundClean() {
            m.fill(0)
        }
        destroy() {
            this.set(0, 0, 0, 0, 0, 0, 0, 0),
            this.buffer.fill(0)
        }
    }
    class x extends E {
        constructor() {
            super(),
            this.A = -1056596264,
            this.B = 914150663,
            this.C = 812702999,
            this.D = -150054599,
            this.E = -4191439,
            this.F = 1750603025,
            this.G = 1694076839,
            this.H = -1090891868,
            this.outputLen = 28
        }
    }
    const B = d((()=>new E))
      , A = (d((()=>new x)),
    BigInt(0))
      , v = BigInt(1)
      , S = BigInt(2)
      , I = t=>t instanceof Uint8Array
      , O = Array.from({
        length: 256
    }, ((t,e)=>e.toString(16).padStart(2, "0")));
    function L(t) {
        if (!I(t))
            throw new Error("Uint8Array expected");
        let e = "";
        for (let n = 0; n < t.length; n++)
            e += O[t[n]];
        return e
    }
    function U(t) {
        const e = t.toString(16);
        return 1 & e.length ? `0${e}` : e
    }
    function H(t) {
        if ("string" != typeof t)
            throw new Error("hex string expected, got " + typeof t);
        return BigInt("" === t ? "0" : `0x${t}`)
    }
    function R(t) {
        if ("string" != typeof t)
            throw new Error("hex string expected, got " + typeof t);
        if (t.length % 2)
            throw new Error("hex string is invalid: unpadded " + t.length);
        const e = new Uint8Array(t.length / 2);
        for (let n = 0; n < e.length; n++) {
            const r = 2 * n
              , i = t.slice(r, r + 2)
              , o = Number.parseInt(i, 16);
            if (Number.isNaN(o) || o < 0)
                throw new Error("invalid byte sequence");
            e[n] = o
        }
        return e
    }
    function T(t) {
        return H(L(t))
    }
    function q(t) {
        if (!I(t))
            throw new Error("Uint8Array expected");
        return H(L(Uint8Array.from(t).reverse()))
    }
    const N = (t,e)=>R(t.toString(16).padStart(2 * e, "0"))
      , D = (t,e)=>N(t, e).reverse()
      , F = t=>R(U(t));
    function C(t, e, n) {
        let r;
        if ("string" == typeof e)
            try {
                r = R(e)
            } catch (n) {
                throw new Error(`${t} must be valid hex string, got "${e}". Cause: ${n}`)
            }
        else {
            if (!I(e))
                throw new Error(`${t} must be hex string or Uint8Array`);
            r = Uint8Array.from(e)
        }
        const i = r.length;
        if ("number" == typeof n && i !== n)
            throw new Error(`${t} expected ${n} bytes, got ${i}`);
        return r
    }
    function k(...t) {
        const e = new Uint8Array(t.reduce(((t,e)=>t + e.length), 0));
        let n = 0;
        return t.forEach((t=>{
            if (!I(t))
                throw new Error("Uint8Array expected");
            e.set(t, n),
            n += t.length
        }
        )),
        e
    }
    function P(t, e) {
        if (t.length !== e.length)
            return !1;
        for (let n = 0; n < t.length; n++)
            if (t[n] !== e[n])
                return !1;
        return !0
    }
    function $(t) {
        if ("string" != typeof t)
            throw new Error("utf8ToBytes expected string, got " + typeof t);
        return (new TextEncoder).encode(t)
    }
    function _(t) {
        let e;
        for (e = 0; t > 0n; t >>= v,
        e += 1)
            ;
        return e
    }
    const Z = (t,e)=>t >> BigInt(e) & 1n
      , V = (t,e,n)=>t | (n ? v : A) << BigInt(e)
      , j = t=>(S << BigInt(t - 1)) - v
      , z = t=>new Uint8Array(t)
      , G = t=>Uint8Array.from(t);
    function K(t, e, n) {
        if ("number" != typeof t || t < 2)
            throw new Error("hashLen must be a number");
        if ("number" != typeof e || e < 2)
            throw new Error("qByteLen must be a number");
        if ("function" != typeof n)
            throw new Error("hmacFn must be a function");
        let r = z(t)
          , i = z(t)
          , o = 0;
        const s = ()=>{
            r.fill(1),
            i.fill(0),
            o = 0
        }
          , f = (...t)=>n(i, r, ...t)
          , a = (t=z())=>{
            i = f(G([0]), t),
            r = f(),
            0 !== t.length && (i = f(G([1]), t),
            r = f())
        }
          , c = ()=>{
            if (o++ >= 1e3)
                throw new Error("drbg: tried 1000 values");
            let t = 0;
            const n = [];
            for (; t < e; ) {
                r = f();
                const e = r.slice();
                n.push(e),
                t += r.length
            }
            return k(...n)
        }
        ;
        return (t,e)=>{
            let n;
            for (s(),
            a(t); !(n = e(c())); )
                a();
            return s(),
            n
        }
    }
    const M = {
        bigint: t=>"bigint" == typeof t,
        function: t=>"function" == typeof t,
        boolean: t=>"boolean" == typeof t,
        string: t=>"string" == typeof t,
        isSafeInteger: t=>Number.isSafeInteger(t),
        array: t=>Array.isArray(t),
        field: (t,e)=>e.Fp.isValid(t),
        hash: t=>"function" == typeof t && Number.isSafeInteger(t.outputLen)
    };
    function W(t, e, n={}) {
        const r = (e,n,r)=>{
            const i = M[n];
            if ("function" != typeof i)
                throw new Error(`Invalid validator "${n}", expected function`);
            const o = t[e];
            if (!(r && void 0 === o || i(o, t)))
                throw new Error(`Invalid param ${String(e)}=${o} (${typeof o}), expected ${n}`)
        }
        ;
        for (const [t,n] of Object.entries(e))
            r(t, n, !1);
        for (const [t,e] of Object.entries(n))
            r(t, e, !0);
        return t
    }
    const Y = BigInt(0)
      , X = BigInt(1)
      , J = BigInt(2)
      , Q = BigInt(3)
      , tt = BigInt(4)
      , et = BigInt(5)
      , nt = BigInt(8);
    function rt(t, e) {
        const n = t % e;
        return n >= Y ? n : e + n
    }
    function it(t, e, n) {
        if (n <= Y || e < Y)
            throw new Error("Expected power/modulo > 0");
        if (n === X)
            return Y;
        let r = X;
        for (; e > Y; )
            e & X && (r = r * t % n),
            t = t * t % n,
            e >>= X;
        return r
    }
    function ot(t, e, n) {
        let r = t;
        for (; e-- > Y; )
            r *= r,
            r %= n;
        return r
    }
    function st(t, e) {
        if (t === Y || e <= Y)
            throw new Error(`invert: expected positive integers, got n=${t} mod=${e}`);
        let n = rt(t, e)
          , r = e
          , i = Y
          , o = X
          , s = X
          , f = Y;
        for (; n !== Y; ) {
            const t = r / n
              , e = r % n
              , a = i - s * t
              , c = o - f * t;
            r = n,
            n = e,
            i = s,
            o = f,
            s = a,
            f = c
        }
        if (r !== X)
            throw new Error("invert: does not exist");
        return rt(i, e)
    }
    BigInt(9),
    BigInt(16);
    const ft = ["create", "isValid", "is0", "neg", "inv", "sqrt", "sqr", "eql", "add", "sub", "mul", "pow", "div", "addN", "subN", "mulN", "sqrN"];
    function at(t) {
        return W(t, ft.reduce(((t,e)=>(t[e] = "function",
        t)), {
            ORDER: "bigint",
            MASK: "bigint",
            BYTES: "isSafeInteger",
            BITS: "isSafeInteger"
        }))
    }
    function ct(t, e) {
        const n = void 0 !== e ? e : t.toString(2).length;
        return {
            nBitLength: n,
            nByteLength: Math.ceil(n / 8)
        }
    }
    const ht = BigInt(0)
      , ut = BigInt(1);
    function lt(t) {
        return at(t.Fp),
        W(t, {
            n: "bigint",
            h: "bigint",
            Gx: "field",
            Gy: "field"
        }, {
            nBitLength: "isSafeInteger",
            nByteLength: "isSafeInteger"
        }),
        Object.freeze({
            ...ct(t.n, t.nBitLength),
            ...t
        })
    }
    const {bytesToNumberBE: dt, hexToBytes: bt} = e
      , pt = {
        Err: class extends Error {
            constructor(t="") {
                super(t)
            }
        }
        ,
        _parseInt(t) {
            const {Err: e} = pt;
            if (t.length < 2 || 2 !== t[0])
                throw new e("Invalid signature integer tag");
            const n = t[1]
              , r = t.subarray(2, n + 2);
            if (!n || r.length !== n)
                throw new e("Invalid signature integer: wrong length");
            if (0 === r[0] && r[1] <= 127)
                throw new e("Invalid signature integer: trailing length");
            return {
                d: dt(r),
                l: t.subarray(n + 2)
            }
        },
        toSig(t) {
            const {Err: e} = pt
              , n = "string" == typeof t ? bt(t) : t;
            if (!(n instanceof Uint8Array))
                throw new Error("ui8a expected");
            let r = n.length;
            if (r < 2 || 48 != n[0])
                throw new e("Invalid signature tag");
            if (n[1] !== r - 2)
                throw new e("Invalid signature: incorrect length");
            const {d: i, l: o} = pt._parseInt(n.subarray(2))
              , {d: s, l: f} = pt._parseInt(o);
            if (f.length)
                throw new e("Invalid signature: left bytes after parsing");
            return {
                r: i,
                s
            }
        },
        hexFromSig(t) {
            const e = t=>Number.parseInt(t[0], 16) >= 8 ? "00" + t : t
              , n = t=>{
                const e = t.toString(16);
                return 1 & e.length ? `0${e}` : e
            }
              , r = e(n(t.s))
              , i = e(n(t.r))
              , o = r.length / 2
              , s = i.length / 2
              , f = n(o)
              , a = n(s);
            return `30${n(s + o + 4)}02${a}${i}02${f}${r}`
        }
    }
      , wt = BigInt(0)
      , gt = BigInt(1);
    function yt(t) {
        const e = function(t) {
            const e = lt(t);
            return W(e, {
                hash: "hash",
                hmac: "function",
                randomBytes: "function"
            }, {
                bits2int: "function",
                bits2int_modN: "function",
                lowS: "boolean"
            }),
            Object.freeze({
                lowS: !0,
                ...e
            })
        }(t)
          , n = e.n
          , r = e.Fp
          , i = r.BYTES + 1
          , o = 2 * r.BYTES + 1;
        function s(t) {
            return rt(t, n)
        }
        function f(t) {
            return st(t, n)
        }
        const {ProjectivePoint: a, normPrivateKeyToScalar: c, weierstrassEquation: h, isWithinCurveOrder: u} = function(t) {
            const e = function(t) {
                const e = lt(t);
                W(e, {
                    a: "field",
                    b: "field",
                    fromBytes: "function",
                    toBytes: "function"
                }, {
                    allowedPrivateKeyLengths: "array",
                    wrapPrivateKey: "boolean",
                    isTorsionFree: "function",
                    clearCofactor: "function",
                    allowInfinityPoint: "boolean"
                });
                const {endo: n, Fp: r, a: i} = e;
                if (n) {
                    if (!r.eql(i, r.ZERO))
                        throw new Error("Endomorphism can only be defined for Koblitz curves that have a=0");
                    if ("object" != typeof n || "bigint" != typeof n.beta || "function" != typeof n.splitScalar)
                        throw new Error("Expected endomorphism with beta: bigint and splitScalar: function")
                }
                return Object.freeze({
                    ...e
                })
            }(t)
              , {Fp: n} = e;
            function r(t) {
                const {a: r, b: i} = e
                  , o = n.sqr(t)
                  , s = n.mul(o, t);
                return n.add(n.add(s, n.mul(t, r)), i)
            }
            function i(t) {
                return "bigint" == typeof t && wt < t && t < e.n
            }
            function o(t) {
                if (!i(t))
                    throw new Error("Expected valid bigint: 0 < bigint < curve.n")
            }
            function s(t) {
                const {allowedPrivateKeyLengths: n, nByteLength: r, wrapPrivateKey: i, n: s} = e;
                if (n && "bigint" != typeof t) {
                    if (t instanceof Uint8Array && (t = L(t)),
                    "string" != typeof t || !n.includes(t.length))
                        throw new Error("Invalid key");
                    t = t.padStart(2 * r, "0")
                }
                let f;
                try {
                    f = "bigint" == typeof t ? t : T(C("private key", t, r))
                } catch (e) {
                    throw new Error(`private key must be ${r} bytes, hex or bigint, not ${typeof t}`)
                }
                return i && (f = rt(f, s)),
                o(f),
                f
            }
            const f = new Map;
            function a(t) {
                if (!(t instanceof c))
                    throw new Error("ProjectivePoint expected")
            }
            class c {
                constructor(t, e, r) {
                    if (this.px = t,
                    this.py = e,
                    this.pz = r,
                    null == t || !n.isValid(t))
                        throw new Error("x required");
                    if (null == e || !n.isValid(e))
                        throw new Error("y required");
                    if (null == r || !n.isValid(r))
                        throw new Error("z required")
                }
                static fromAffine(t) {
                    const {x: e, y: r} = t || {};
                    if (!t || !n.isValid(e) || !n.isValid(r))
                        throw new Error("invalid affine point");
                    if (t instanceof c)
                        throw new Error("projective point not allowed");
                    const i = t=>n.eql(t, n.ZERO);
                    return i(e) && i(r) ? c.ZERO : new c(e,r,n.ONE)
                }
                get x() {
                    return this.toAffine().x
                }
                get y() {
                    return this.toAffine().y
                }
                static normalizeZ(t) {
                    const e = n.invertBatch(t.map((t=>t.pz)));
                    return t.map(((t,n)=>t.toAffine(e[n]))).map(c.fromAffine)
                }
                static fromHex(t) {
                    const n = c.fromAffine(e.fromBytes(C("pointHex", t)));
                    return n.assertValidity(),
                    n
                }
                static fromPrivateKey(t) {
                    return c.BASE.multiply(s(t))
                }
                _setWindowSize(t) {
                    this._WINDOW_SIZE = t,
                    f.delete(this)
                }
                assertValidity() {
                    if (this.is0()) {
                        if (e.allowInfinityPoint)
                            return;
                        throw new Error("bad point: ZERO")
                    }
                    const {x: t, y: i} = this.toAffine();
                    if (!n.isValid(t) || !n.isValid(i))
                        throw new Error("bad point: x or y not FE");
                    const o = n.sqr(i)
                      , s = r(t);
                    if (!n.eql(o, s))
                        throw new Error("bad point: equation left !=right");
                    if (!this.isTorsionFree())
                        throw new Error("bad point: not in prime-order subgroup")
                }
                hasEvenY() {
                    const {y: t} = this.toAffine();
                    if (n.isOdd)
                        return !n.isOdd(t);
                    throw new Error("Field doesn't support isOdd")
                }
                equals(t) {
                    a(t);
                    const {px: e, py: r, pz: i} = this
                      , {px: o, py: s, pz: f} = t
                      , c = n.eql(n.mul(e, f), n.mul(o, i))
                      , h = n.eql(n.mul(r, f), n.mul(s, i));
                    return c && h
                }
                negate() {
                    return new c(this.px,n.neg(this.py),this.pz)
                }
                double() {
                    const {a: t, b: r} = e
                      , i = n.mul(r, 3n)
                      , {px: o, py: s, pz: f} = this;
                    let a = n.ZERO
                      , h = n.ZERO
                      , u = n.ZERO
                      , l = n.mul(o, o)
                      , d = n.mul(s, s)
                      , b = n.mul(f, f)
                      , p = n.mul(o, s);
                    return p = n.add(p, p),
                    u = n.mul(o, f),
                    u = n.add(u, u),
                    a = n.mul(t, u),
                    h = n.mul(i, b),
                    h = n.add(a, h),
                    a = n.sub(d, h),
                    h = n.add(d, h),
                    h = n.mul(a, h),
                    a = n.mul(p, a),
                    u = n.mul(i, u),
                    b = n.mul(t, b),
                    p = n.sub(l, b),
                    p = n.mul(t, p),
                    p = n.add(p, u),
                    u = n.add(l, l),
                    l = n.add(u, l),
                    l = n.add(l, b),
                    l = n.mul(l, p),
                    h = n.add(h, l),
                    b = n.mul(s, f),
                    b = n.add(b, b),
                    l = n.mul(b, p),
                    a = n.sub(a, l),
                    u = n.mul(b, d),
                    u = n.add(u, u),
                    u = n.add(u, u),
                    new c(a,h,u)
                }
                add(t) {
                    a(t);
                    const {px: r, py: i, pz: o} = this
                      , {px: s, py: f, pz: h} = t;
                    let u = n.ZERO
                      , l = n.ZERO
                      , d = n.ZERO;
                    const b = e.a
                      , p = n.mul(e.b, 3n);
                    let w = n.mul(r, s)
                      , g = n.mul(i, f)
                      , y = n.mul(o, h)
                      , m = n.add(r, i)
                      , E = n.add(s, f);
                    m = n.mul(m, E),
                    E = n.add(w, g),
                    m = n.sub(m, E),
                    E = n.add(r, o);
                    let x = n.add(s, h);
                    return E = n.mul(E, x),
                    x = n.add(w, y),
                    E = n.sub(E, x),
                    x = n.add(i, o),
                    u = n.add(f, h),
                    x = n.mul(x, u),
                    u = n.add(g, y),
                    x = n.sub(x, u),
                    d = n.mul(b, E),
                    u = n.mul(p, y),
                    d = n.add(u, d),
                    u = n.sub(g, d),
                    d = n.add(g, d),
                    l = n.mul(u, d),
                    g = n.add(w, w),
                    g = n.add(g, w),
                    y = n.mul(b, y),
                    E = n.mul(p, E),
                    g = n.add(g, y),
                    y = n.sub(w, y),
                    y = n.mul(b, y),
                    E = n.add(E, y),
                    w = n.mul(g, E),
                    l = n.add(l, w),
                    w = n.mul(x, E),
                    u = n.mul(m, u),
                    u = n.sub(u, w),
                    w = n.mul(m, g),
                    d = n.mul(x, d),
                    d = n.add(d, w),
                    new c(u,l,d)
                }
                subtract(t) {
                    return this.add(t.negate())
                }
                is0() {
                    return this.equals(c.ZERO)
                }
                wNAF(t) {
                    return u.wNAFCached(this, f, t, (t=>{
                        const e = n.invertBatch(t.map((t=>t.pz)));
                        return t.map(((t,n)=>t.toAffine(e[n]))).map(c.fromAffine)
                    }
                    ))
                }
                multiplyUnsafe(t) {
                    const r = c.ZERO;
                    if (t === wt)
                        return r;
                    if (o(t),
                    t === gt)
                        return this;
                    const {endo: i} = e;
                    if (!i)
                        return u.unsafeLadder(this, t);
                    let {k1neg: s, k1: f, k2neg: a, k2: h} = i.splitScalar(t)
                      , l = r
                      , d = r
                      , b = this;
                    for (; f > wt || h > wt; )
                        f & gt && (l = l.add(b)),
                        h & gt && (d = d.add(b)),
                        b = b.double(),
                        f >>= gt,
                        h >>= gt;
                    return s && (l = l.negate()),
                    a && (d = d.negate()),
                    d = new c(n.mul(d.px, i.beta),d.py,d.pz),
                    l.add(d)
                }
                multiply(t) {
                    o(t);
                    let r, i, s = t;
                    const {endo: f} = e;
                    if (f) {
                        const {k1neg: t, k1: e, k2neg: o, k2: a} = f.splitScalar(s);
                        let {p: h, f: l} = this.wNAF(e)
                          , {p: d, f: b} = this.wNAF(a);
                        h = u.constTimeNegate(t, h),
                        d = u.constTimeNegate(o, d),
                        d = new c(n.mul(d.px, f.beta),d.py,d.pz),
                        r = h.add(d),
                        i = l.add(b)
                    } else {
                        const {p: t, f: e} = this.wNAF(s);
                        r = t,
                        i = e
                    }
                    return c.normalizeZ([r, i])[0]
                }
                multiplyAndAddUnsafe(t, e, n) {
                    const r = c.BASE
                      , i = (t,e)=>e !== wt && e !== gt && t.equals(r) ? t.multiply(e) : t.multiplyUnsafe(e)
                      , o = i(this, e).add(i(t, n));
                    return o.is0() ? void 0 : o
                }
                toAffine(t) {
                    const {px: e, py: r, pz: i} = this
                      , o = this.is0();
                    null == t && (t = o ? n.ONE : n.inv(i));
                    const s = n.mul(e, t)
                      , f = n.mul(r, t)
                      , a = n.mul(i, t);
                    if (o)
                        return {
                            x: n.ZERO,
                            y: n.ZERO
                        };
                    if (!n.eql(a, n.ONE))
                        throw new Error("invZ was invalid");
                    return {
                        x: s,
                        y: f
                    }
                }
                isTorsionFree() {
                    const {h: t, isTorsionFree: n} = e;
                    if (t === gt)
                        return !0;
                    if (n)
                        return n(c, this);
                    throw new Error("isTorsionFree() has not been declared for the elliptic curve")
                }
                clearCofactor() {
                    const {h: t, clearCofactor: n} = e;
                    return t === gt ? this : n ? n(c, this) : this.multiplyUnsafe(e.h)
                }
                toRawBytes(t=!0) {
                    return this.assertValidity(),
                    e.toBytes(c, this, t)
                }
                toHex(t=!0) {
                    return L(this.toRawBytes(t))
                }
            }
            c.BASE = new c(e.Gx,e.Gy,n.ONE),
            c.ZERO = new c(n.ZERO,n.ONE,n.ZERO);
            const h = e.nBitLength
              , u = function(t, e) {
                const n = (t,e)=>{
                    const n = e.negate();
                    return t ? n : e
                }
                  , r = t=>({
                    windows: Math.ceil(e / t) + 1,
                    windowSize: 2 ** (t - 1)
                });
                return {
                    constTimeNegate: n,
                    unsafeLadder(e, n) {
                        let r = t.ZERO
                          , i = e;
                        for (; n > ht; )
                            n & ut && (r = r.add(i)),
                            i = i.double(),
                            n >>= ut;
                        return r
                    },
                    precomputeWindow(t, e) {
                        const {windows: n, windowSize: i} = r(e)
                          , o = [];
                        let s = t
                          , f = s;
                        for (let t = 0; t < n; t++) {
                            f = s,
                            o.push(f);
                            for (let t = 1; t < i; t++)
                                f = f.add(s),
                                o.push(f);
                            s = f.double()
                        }
                        return o
                    },
                    wNAF(e, i, o) {
                        const {windows: s, windowSize: f} = r(e);
                        let a = t.ZERO
                          , c = t.BASE;
                        const h = BigInt(2 ** e - 1)
                          , u = 2 ** e
                          , l = BigInt(e);
                        for (let t = 0; t < s; t++) {
                            const e = t * f;
                            let r = Number(o & h);
                            o >>= l,
                            r > f && (r -= u,
                            o += ut);
                            const s = e
                              , d = e + Math.abs(r) - 1
                              , b = t % 2 != 0
                              , p = r < 0;
                            0 === r ? c = c.add(n(b, i[s])) : a = a.add(n(p, i[d]))
                        }
                        return {
                            p: a,
                            f: c
                        }
                    },
                    wNAFCached(t, e, n, r) {
                        const i = t._WINDOW_SIZE || 1;
                        let o = e.get(t);
                        return o || (o = this.precomputeWindow(t, i),
                        1 !== i && e.set(t, r(o))),
                        this.wNAF(i, o, n)
                    }
                }
            }(c, e.endo ? Math.ceil(h / 2) : h);
            return {
                ProjectivePoint: c,
                normPrivateKeyToScalar: s,
                weierstrassEquation: r,
                isWithinCurveOrder: i
            }
        }({
            ...e,
            toBytes(t, e, n) {
                const i = e.toAffine()
                  , o = r.toBytes(i.x)
                  , s = k;
                return n ? s(Uint8Array.from([e.hasEvenY() ? 2 : 3]), o) : s(Uint8Array.from([4]), o, r.toBytes(i.y))
            },
            fromBytes(t) {
                const e = t.length
                  , n = t[0]
                  , s = t.subarray(1);
                if (e !== i || 2 !== n && 3 !== n) {
                    if (e === o && 4 === n)
                        return {
                            x: r.fromBytes(s.subarray(0, r.BYTES)),
                            y: r.fromBytes(s.subarray(r.BYTES, 2 * r.BYTES))
                        };
                    throw new Error(`Point of length ${e} was invalid. Expected ${i} compressed bytes or ${o} uncompressed bytes`)
                }
                {
                    const t = T(s);
                    if (!(wt < (f = t) && f < r.ORDER))
                        throw new Error("Point is not on curve");
                    const e = h(t);
                    let i = r.sqrt(e);
                    return 1 == (1 & n) != ((i & gt) === gt) && (i = r.neg(i)),
                    {
                        x: t,
                        y: i
                    }
                }
                var f
            }
        })
          , l = t=>L(N(t, e.nByteLength));
        function d(t) {
            return t > n >> gt
        }
        const b = (t,e,n)=>T(t.slice(e, n));
        class p {
            constructor(t, e, n) {
                this.r = t,
                this.s = e,
                this.recovery = n,
                this.assertValidity()
            }
            static fromCompact(t) {
                const n = e.nByteLength;
                return t = C("compactSignature", t, 2 * n),
                new p(b(t, 0, n),b(t, n, 2 * n))
            }
            static fromDER(t) {
                const {r: e, s: n} = pt.toSig(C("DER", t));
                return new p(e,n)
            }
            assertValidity() {
                if (!u(this.r))
                    throw new Error("r must be 0 < r < CURVE.n");
                if (!u(this.s))
                    throw new Error("s must be 0 < s < CURVE.n")
            }
            addRecoveryBit(t) {
                return new p(this.r,this.s,t)
            }
            recoverPublicKey(t) {
                const {r: n, s: i, recovery: o} = this
                  , c = m(C("msgHash", t));
                if (null == o || ![0, 1, 2, 3].includes(o))
                    throw new Error("recovery id invalid");
                const h = 2 === o || 3 === o ? n + e.n : n;
                if (h >= r.ORDER)
                    throw new Error("recovery id 2 or 3 invalid");
                const u = 0 == (1 & o) ? "02" : "03"
                  , d = a.fromHex(u + l(h))
                  , b = f(h)
                  , p = s(-c * b)
                  , w = s(i * b)
                  , g = a.BASE.multiplyAndAddUnsafe(d, p, w);
                if (!g)
                    throw new Error("point at infinify");
                return g.assertValidity(),
                g
            }
            hasHighS() {
                return d(this.s)
            }
            normalizeS() {
                return this.hasHighS() ? new p(this.r,s(-this.s),this.recovery) : this
            }
            toDERRawBytes() {
                return R(this.toDERHex())
            }
            toDERHex() {
                return pt.hexFromSig({
                    r: this.r,
                    s: this.s
                })
            }
            toCompactRawBytes() {
                return R(this.toCompactHex())
            }
            toCompactHex() {
                return l(this.r) + l(this.s)
            }
        }
        const w = {
            isValidPrivateKey(t) {
                try {
                    return c(t),
                    !0
                } catch (t) {
                    return !1
                }
            },
            normPrivateKeyToScalar: c,
            randomPrivateKey: ()=>{
                const t = function(t, e, n=!1) {
                    const r = (t = C("privateHash", t)).length
                      , i = ct(e).nByteLength + 8;
                    if (i < 24 || r < i || r > 1024)
                        throw new Error(`hashToPrivateScalar: expected ${i}-1024 bytes of input, got ${r}`);
                    return rt(n ? q(t) : T(t), e - X) + X
                }(e.randomBytes(r.BYTES + 8), n);
                return N(t, e.nByteLength)
            }
            ,
            precompute: (t=8,e=a.BASE)=>(e._setWindowSize(t),
            e.multiply(BigInt(3)),
            e)
        };
        function g(t) {
            const e = t instanceof Uint8Array
              , n = "string" == typeof t
              , r = (e || n) && t.length;
            return e ? r === i || r === o : n ? r === 2 * i || r === 2 * o : t instanceof a
        }
        const y = e.bits2int || function(t) {
            const n = T(t)
              , r = 8 * t.length - e.nBitLength;
            return r > 0 ? n >> BigInt(r) : n
        }
          , m = e.bits2int_modN || function(t) {
            return s(y(t))
        }
          , E = j(e.nBitLength);
        function x(t) {
            if ("bigint" != typeof t)
                throw new Error("bigint expected");
            if (!(wt <= t && t < E))
                throw new Error(`bigint expected < 2^${e.nBitLength}`);
            return N(t, e.nByteLength)
        }
        const B = {
            lowS: e.lowS,
            prehash: !1
        }
          , A = {
            lowS: e.lowS,
            prehash: !1
        };
        return a.BASE._setWindowSize(8),
        {
            CURVE: e,
            getPublicKey: function(t, e=!0) {
                return a.fromPrivateKey(t).toRawBytes(e)
            },
            getSharedSecret: function(t, e, n=!0) {
                if (g(t))
                    throw new Error("first arg must be private key");
                if (!g(e))
                    throw new Error("second arg must be public key");
                return a.fromHex(e).multiply(c(t)).toRawBytes(n)
            },
            sign: function(t, n, i=B) {
                const {seed: o, k2sig: h} = function(t, n, i=B) {
                    if (["recovered", "canonical"].some((t=>t in i)))
                        throw new Error("sign() legacy options not supported");
                    const {hash: o, randomBytes: h} = e;
                    let {lowS: l, prehash: b, extraEntropy: g} = i;
                    null == l && (l = !0),
                    t = C("msgHash", t),
                    b && (t = C("prehashed msgHash", o(t)));
                    const E = m(t)
                      , A = c(n)
                      , v = [x(A), x(E)];
                    if (null != g) {
                        const t = !0 === g ? h(r.BYTES) : g;
                        v.push(C("extraEntropy", t, r.BYTES))
                    }
                    const S = k(...v)
                      , I = E;
                    return {
                        seed: S,
                        k2sig: function(t) {
                            const e = y(t);
                            if (!u(e))
                                return;
                            const n = f(e)
                              , r = a.BASE.multiply(e).toAffine()
                              , i = s(r.x);
                            if (i === wt)
                                return;
                            const o = T(w.randomPrivateKey())
                              , c = f(o)
                              , h = s(o * A * i)
                              , b = s(o * I)
                              , g = s(c * s(h + b))
                              , m = s(n * g);
                            if (m === wt)
                                return;
                            let E = (r.x === i ? 0 : 2) | Number(r.y & gt)
                              , x = m;
                            return l && d(m) && (x = function(t) {
                                return d(t) ? s(-t) : t
                            }(m),
                            E ^= 1),
                            new p(i,x,E)
                        }
                    }
                }(t, n, i);
                return K(e.hash.outputLen, e.nByteLength, e.hmac)(o, h)
            },
            verify: function(t, n, r, i=A) {
                const o = t;
                if (n = C("msgHash", n),
                r = C("publicKey", r),
                "strict"in i)
                    throw new Error("options.strict was renamed to lowS");
                const {lowS: c, prehash: h} = i;
                let u, l;
                try {
                    if ("string" == typeof o || o instanceof Uint8Array)
                        try {
                            u = p.fromDER(o)
                        } catch (t) {
                            if (!(t instanceof pt.Err))
                                throw t;
                            u = p.fromCompact(o)
                        }
                    else {
                        if ("object" != typeof o || "bigint" != typeof o.r || "bigint" != typeof o.s)
                            throw new Error("PARSE");
                        {
                            const {r: t, s: e} = o;
                            u = new p(t,e)
                        }
                    }
                    l = a.fromHex(r)
                } catch (t) {
                    if ("PARSE" === t.message)
                        throw new Error("signature must be Signature instance, Uint8Array or hex string");
                    return !1
                }
                if (c && u.hasHighS())
                    return !1;
                h && (n = e.hash(n));
                const {r: d, s: b} = u
                  , w = m(n)
                  , g = f(b)
                  , y = s(w * g)
                  , E = s(d * g)
                  , x = a.BASE.multiplyAndAddUnsafe(l, y, E)?.toAffine();
                return !!x && s(x.x) === d
            },
            ProjectivePoint: a,
            Signature: p,
            utils: w
        }
    }
    const mt = T;
    function Et(t, e) {
        if (t < 0 || t >= 1 << 8 * e)
            throw new Error(`bad I2OSP call: value=${t} length=${e}`);
        const n = Array.from({
            length: e
        }).fill(0);
        for (let r = e - 1; r >= 0; r--)
            n[r] = 255 & t,
            t >>>= 8;
        return new Uint8Array(n)
    }
    function xt(t, e) {
        const n = new Uint8Array(t.length);
        for (let r = 0; r < t.length; r++)
            n[r] = t[r] ^ e[r];
        return n
    }
    function Bt(t) {
        if (!(t instanceof Uint8Array))
            throw new Error("Uint8Array expected")
    }
    function At(t) {
        if (!Number.isSafeInteger(t))
            throw new Error("number expected")
    }
    function vt(t, e, n) {
        const {p: r, k: i, m: o, hash: s, expand: f, DST: a} = n;
        Bt(t),
        At(e);
        const c = function(t) {
            if (t instanceof Uint8Array)
                return t;
            if ("string" == typeof t)
                return $(t);
            throw new Error("DST must be Uint8Array or string")
        }(a)
          , h = r.toString(2).length
          , u = Math.ceil((h + i) / 8)
          , l = e * o * u;
        let d;
        if ("xmd" === f)
            d = function(t, e, n, r) {
                Bt(t),
                Bt(e),
                At(n),
                e.length > 255 && (e = r(k($("H2C-OVERSIZE-DST-"), e)));
                const {outputLen: i, blockLen: o} = r
                  , s = Math.ceil(n / i);
                if (s > 255)
                    throw new Error("Invalid xmd length");
                const f = k(e, Et(e.length, 1))
                  , a = Et(0, o)
                  , c = Et(n, 2)
                  , h = new Array(s)
                  , u = r(k(a, t, c, Et(0, 1), f));
                h[0] = r(k(u, Et(1, 1), f));
                for (let t = 1; t <= s; t++) {
                    const e = [xt(u, h[t - 1]), Et(t + 1, 1), f];
                    h[t] = r(k(...e))
                }
                return k(...h).slice(0, n)
            }(t, c, l, s);
        else if ("xof" === f)
            d = function(t, e, n, r, i) {
                if (Bt(t),
                Bt(e),
                At(n),
                e.length > 255) {
                    const t = Math.ceil(2 * r / 8);
                    e = i.create({
                        dkLen: t
                    }).update($("H2C-OVERSIZE-DST-")).update(e).digest()
                }
                if (n > 65535 || e.length > 255)
                    throw new Error("expand_message_xof: invalid lenInBytes");
                return i.create({
                    dkLen: n
                }).update(t).update(Et(n, 2)).update(e).update(Et(e.length, 1)).digest()
            }(t, c, l, i, s);
        else {
            if (void 0 !== f)
                throw new Error('expand must be "xmd", "xof" or undefined');
            d = t
        }
        const b = new Array(e);
        for (let t = 0; t < e; t++) {
            const e = new Array(o);
            for (let n = 0; n < o; n++) {
                const i = u * (n + t * o)
                  , s = d.subarray(i, i + u);
                e[n] = rt(mt(s), r)
            }
            b[t] = e
        }
        return b
    }
    class St extends u {
        constructor(t, e) {
            super(),
            this.finished = !1,
            this.destroyed = !1,
            i.hash(t);
            const n = h(e);
            if (this.iHash = t.create(),
            "function" != typeof this.iHash.update)
                throw new TypeError("Expected instance of class which extends utils.Hash");
            this.blockLen = this.iHash.blockLen,
            this.outputLen = this.iHash.outputLen;
            const r = this.blockLen
              , o = new Uint8Array(r);
            o.set(n.length > r ? t.create().update(n).digest() : n);
            for (let t = 0; t < o.length; t++)
                o[t] ^= 54;
            this.iHash.update(o),
            this.oHash = t.create();
            for (let t = 0; t < o.length; t++)
                o[t] ^= 106;
            this.oHash.update(o),
            o.fill(0)
        }
        update(t) {
            return i.exists(this),
            this.iHash.update(t),
            this
        }
        digestInto(t) {
            i.exists(this),
            i.bytes(t, this.outputLen),
            this.finished = !0,
            this.iHash.digestInto(t),
            this.oHash.update(t),
            this.oHash.digestInto(t),
            this.destroy()
        }
        digest() {
            const t = new Uint8Array(this.oHash.outputLen);
            return this.digestInto(t),
            t
        }
        _cloneInto(t) {
            t || (t = Object.create(Object.getPrototypeOf(this), {}));
            const {oHash: e, iHash: n, finished: r, destroyed: i, blockLen: o, outputLen: s} = this;
            return t.finished = r,
            t.destroyed = i,
            t.blockLen = o,
            t.outputLen = s,
            t.oHash = e._cloneInto(t.oHash),
            t.iHash = n._cloneInto(t.iHash),
            t
        }
        destroy() {
            this.destroyed = !0,
            this.oHash.destroy(),
            this.iHash.destroy()
        }
    }
    const It = (t,e,n)=>new St(t,e).update(n).digest();
    function Ot(t) {
        return {
            hash: t,
            hmac: (e,...n)=>It(t, e, function(...t) {
                if (!t.every((t=>t instanceof Uint8Array)))
                    throw new Error("Uint8Array list expected");
                if (1 === t.length)
                    return t[0];
                const e = t.reduce(((t,e)=>t + e.length), 0)
                  , n = new Uint8Array(e);
                for (let e = 0, r = 0; e < t.length; e++) {
                    const i = t[e];
                    n.set(i, r),
                    r += i.length
                }
                return n
            }(...n)),
            randomBytes: b
        }
    }
    It.create = (t,e)=>new St(t,e);
    const Lt = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
      , Ut = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
      , Ht = BigInt(1)
      , Rt = BigInt(2)
      , Tt = (t,e)=>(t + e / Rt) / e;
    function qt(t) {
        const e = Lt
          , n = BigInt(3)
          , r = BigInt(6)
          , i = BigInt(11)
          , o = BigInt(22)
          , s = BigInt(23)
          , f = BigInt(44)
          , a = BigInt(88)
          , c = t * t * t % e
          , h = c * c * t % e
          , u = ot(h, n, e) * h % e
          , l = ot(u, n, e) * h % e
          , d = ot(l, Rt, e) * c % e
          , b = ot(d, i, e) * d % e
          , p = ot(b, o, e) * b % e
          , w = ot(p, f, e) * p % e
          , g = ot(w, a, e) * w % e
          , y = ot(g, f, e) * p % e
          , m = ot(y, n, e) * h % e
          , E = ot(m, s, e) * b % e
          , x = ot(E, r, e) * c % e
          , B = ot(x, Rt, e);
        if (!Nt.eql(Nt.sqr(B), t))
            throw new Error("Cannot find square root");
        return B
    }
    const Nt = function(t, e, n=!1, r={}) {
        if (t <= Y)
            throw new Error(`Expected Fp ORDER > 0, got ${t}`);
        const {nBitLength: i, nByteLength: o} = ct(t, e);
        if (o > 2048)
            throw new Error("Field lengths over 2048 bytes are not supported");
        const s = function(t) {
            if (t % tt === Q) {
                const e = (t + X) / tt;
                return function(t, n) {
                    const r = t.pow(n, e);
                    if (!t.eql(t.sqr(r), n))
                        throw new Error("Cannot find square root");
                    return r
                }
            }
            if (t % nt === et) {
                const e = (t - et) / nt;
                return function(t, n) {
                    const r = t.mul(n, J)
                      , i = t.pow(r, e)
                      , o = t.mul(n, i)
                      , s = t.mul(t.mul(o, J), i)
                      , f = t.mul(o, t.sub(s, t.ONE));
                    if (!t.eql(t.sqr(f), n))
                        throw new Error("Cannot find square root");
                    return f
                }
            }
            return function(t) {
                const e = (t - X) / J;
                let n, r, i;
                for (n = t - X,
                r = 0; n % J === Y; n /= J,
                r++)
                    ;
                for (i = J; i < t && it(i, e, t) !== t - X; i++)
                    ;
                if (1 === r) {
                    const e = (t + X) / tt;
                    return function(t, n) {
                        const r = t.pow(n, e);
                        if (!t.eql(t.sqr(r), n))
                            throw new Error("Cannot find square root");
                        return r
                    }
                }
                const o = (n + X) / J;
                return function(t, s) {
                    if (t.pow(s, e) === t.neg(t.ONE))
                        throw new Error("Cannot find square root");
                    let f = r
                      , a = t.pow(t.mul(t.ONE, i), n)
                      , c = t.pow(s, o)
                      , h = t.pow(s, n);
                    for (; !t.eql(h, t.ONE); ) {
                        if (t.eql(h, t.ZERO))
                            return t.ZERO;
                        let e = 1;
                        for (let n = t.sqr(h); e < f && !t.eql(n, t.ONE); e++)
                            n = t.sqr(n);
                        const n = t.pow(a, X << BigInt(f - e - 1));
                        a = t.sqr(n),
                        c = t.mul(c, n),
                        h = t.mul(h, a),
                        f = e
                    }
                    return c
                }
            }(t)
        }(t)
          , f = Object.freeze({
            ORDER: t,
            BITS: i,
            BYTES: o,
            MASK: j(i),
            ZERO: Y,
            ONE: X,
            create: e=>rt(e, t),
            isValid: e=>{
                if ("bigint" != typeof e)
                    throw new Error("Invalid field element: expected bigint, got " + typeof e);
                return Y <= e && e < t
            }
            ,
            is0: t=>t === Y,
            isOdd: t=>(t & X) === X,
            neg: e=>rt(-e, t),
            eql: (t,e)=>t === e,
            sqr: e=>rt(e * e, t),
            add: (e,n)=>rt(e + n, t),
            sub: (e,n)=>rt(e - n, t),
            mul: (e,n)=>rt(e * n, t),
            pow: (t,e)=>function(t, e, n) {
                if (n < Y)
                    throw new Error("Expected power > 0");
                if (n === Y)
                    return t.ONE;
                if (n === X)
                    return e;
                let r = t.ONE
                  , i = e;
                for (; n > Y; )
                    n & X && (r = t.mul(r, i)),
                    i = t.sqr(i),
                    n >>= 1n;
                return r
            }(f, t, e),
            div: (e,n)=>rt(e * st(n, t), t),
            sqrN: t=>t * t,
            addN: (t,e)=>t + e,
            subN: (t,e)=>t - e,
            mulN: (t,e)=>t * e,
            inv: e=>st(e, t),
            sqrt: r.sqrt || (t=>s(f, t)),
            invertBatch: t=>function(t, e) {
                const n = new Array(e.length)
                  , r = e.reduce(((e,r,i)=>t.is0(r) ? e : (n[i] = e,
                t.mul(e, r))), t.ONE)
                  , i = t.inv(r);
                return e.reduceRight(((e,r,i)=>t.is0(r) ? e : (n[i] = t.mul(e, n[i]),
                t.mul(e, r))), i),
                n
            }(f, t),
            cmov: (t,e,n)=>n ? e : t,
            toBytes: t=>n ? D(t, o) : N(t, o),
            fromBytes: t=>{
                if (t.length !== o)
                    throw new Error(`Fp.fromBytes: expected ${o}, got ${t.length}`);
                return n ? q(t) : T(t)
            }
        });
        return Object.freeze(f)
    }(Lt, void 0, void 0, {
        sqrt: qt
    })
      , Dt = function(t, e) {
        const n = e=>yt({
            ...t,
            ...Ot(e)
        });
        return Object.freeze({
            ...n(e),
            create: n
        })
    }({
        a: BigInt(0),
        b: BigInt(7),
        Fp: Nt,
        n: Ut,
        Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"),
        h: BigInt(1),
        lowS: !0,
        endo: {
            beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
            splitScalar: t=>{
                const e = Ut
                  , n = BigInt("0x3086d221a7d46bcde86c90e49284eb15")
                  , r = -Ht * BigInt("0xe4437ed6010e88286f547fa90abfe4c3")
                  , i = BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8")
                  , o = n
                  , s = BigInt("0x100000000000000000000000000000000")
                  , f = Tt(o * t, e)
                  , a = Tt(-r * t, e);
                let c = rt(t - f * n - a * i, e)
                  , h = rt(-f * r - a * o, e);
                const u = c > s
                  , l = h > s;
                if (u && (c = e - c),
                l && (h = e - h),
                c > s || h > s)
                    throw new Error("splitScalar: Endomorphism failed, k=" + t);
                return {
                    k1neg: u,
                    k1: c,
                    k2neg: l,
                    k2: h
                }
            }
        }
    }, B);
    BigInt(0);
    Dt.ProjectivePoint;
    Dt.utils.randomPrivateKey;
    const Ft = function(t, e) {
        const n = e.map((t=>Array.from(t).reverse()));
        return (e,r)=>{
            const [i,o,s,f] = n.map((n=>n.reduce(((n,r)=>t.add(t.mul(n, e), r)))));
            return e = t.div(i, o),
            r = t.mul(r, t.div(s, f)),
            {
                x: e,
                y: r
            }
        }
    }(Nt, [["0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7", "0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581", "0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262", "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c"], ["0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b", "0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14", "0x0000000000000000000000000000000000000000000000000000000000000001"], ["0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c", "0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3", "0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931", "0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84"], ["0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b", "0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573", "0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f", "0x0000000000000000000000000000000000000000000000000000000000000001"]].map((t=>t.map((t=>BigInt(t))))))
      , Ct = function(t, e) {
        if (at(t),
        !t.isValid(e.A) || !t.isValid(e.B) || !t.isValid(e.Z))
            throw new Error("mapToCurveSimpleSWU: invalid opts");
        const n = function(t, e) {
            const n = t.ORDER;
            let r = 0n;
            for (let t = n - 1n; t % 2n === 0n; t /= 2n)
                r += 1n;
            const i = r
              , o = (n - 1n) / 2n ** i
              , s = (o - 1n) / 2n
              , f = 2n ** i - 1n
              , a = 2n ** (i - 1n)
              , c = t.pow(e, o)
              , h = t.pow(e, (o + 1n) / 2n);
            let u = (e,n)=>{
                let r = c
                  , o = t.pow(n, f)
                  , u = t.sqr(o);
                u = t.mul(u, n);
                let l = t.mul(e, u);
                l = t.pow(l, s),
                l = t.mul(l, o),
                o = t.mul(l, n),
                u = t.mul(l, e);
                let d = t.mul(u, o);
                l = t.pow(d, a);
                let b = t.eql(l, t.ONE);
                o = t.mul(u, h),
                l = t.mul(d, r),
                u = t.cmov(o, u, b),
                d = t.cmov(l, d, b);
                for (let e = i; e > 1; e--) {
                    let n = 2n ** (e - 2n)
                      , i = t.pow(d, n);
                    const s = t.eql(i, t.ONE);
                    o = t.mul(u, r),
                    r = t.mul(r, r),
                    i = t.mul(d, r),
                    u = t.cmov(o, u, s),
                    d = t.cmov(i, d, s)
                }
                return {
                    isValid: b,
                    value: u
                }
            }
            ;
            if (t.ORDER % 4n === 3n) {
                const n = (t.ORDER - 3n) / 4n
                  , r = t.sqrt(t.neg(e));
                u = (e,i)=>{
                    let o = t.sqr(i);
                    const s = t.mul(e, i);
                    o = t.mul(o, s);
                    let f = t.pow(o, n);
                    f = t.mul(f, s);
                    const a = t.mul(f, r)
                      , c = t.mul(t.sqr(f), i)
                      , h = t.eql(c, e);
                    return {
                        isValid: h,
                        value: t.cmov(a, f, h)
                    }
                }
            }
            return u
        }(t, e.Z);
        if (!t.isOdd)
            throw new Error("Fp.isOdd is not implemented!");
        return r=>{
            let i, o, s, f, a, c, h, u;
            i = t.sqr(r),
            i = t.mul(i, e.Z),
            o = t.sqr(i),
            o = t.add(o, i),
            s = t.add(o, t.ONE),
            s = t.mul(s, e.B),
            f = t.cmov(e.Z, t.neg(o), !t.eql(o, t.ZERO)),
            f = t.mul(f, e.A),
            o = t.sqr(s),
            c = t.sqr(f),
            a = t.mul(c, e.A),
            o = t.add(o, a),
            o = t.mul(o, s),
            c = t.mul(c, f),
            a = t.mul(c, e.B),
            o = t.add(o, a),
            h = t.mul(i, s);
            const {isValid: l, value: d} = n(o, c);
            u = t.mul(i, r),
            u = t.mul(u, d),
            h = t.cmov(h, s, l),
            u = t.cmov(u, d, l);
            const b = t.isOdd(r) === t.isOdd(u);
            return u = t.cmov(t.neg(u), u, b),
            h = t.div(h, f),
            {
                x: h,
                y: u
            }
        }
    }(Nt, {
        A: BigInt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
        B: BigInt("1771"),
        Z: Nt.create(BigInt("-11"))
    })
      , {hashToCurve: kt, encodeToCurve: Pt} = function(t, e, n) {
        return W(n, {
            DST: "string",
            p: "bigint",
            m: "isSafeInteger",
            k: "isSafeInteger",
            hash: "hash"
        }),
        {
            hashToCurve(r, i) {
                const o = vt(r, 2, {
                    ...n,
                    DST: n.DST,
                    ...i
                })
                  , s = t.fromAffine(e(o[0]))
                  , f = t.fromAffine(e(o[1]))
                  , a = s.add(f).clearCofactor();
                return a.assertValidity(),
                a
            },
            encodeToCurve(r, i) {
                const o = vt(r, 1, {
                    ...n,
                    DST: n.encodeDST,
                    ...i
                })
                  , s = t.fromAffine(e(o[0])).clearCofactor();
                return s.assertValidity(),
                s
            }
        }
    }(Dt.ProjectivePoint, (t=>{
        const {x: e, y: n} = Ct(Nt.create(t[0]));
        return Ft(e, n)
    }
    ), {
        DST: "secp256k1_XMD:SHA-256_SSWU_RO_",
        encodeDST: "secp256k1_XMD:SHA-256_SSWU_NU_",
        p: Nt.ORDER,
        m: 1,
        k: 128,
        expand: "xmd",
        hash: B
    });
    function $t(t, e, n, r) {
        i.hash(t);
        const o = function(t, e) {
            if (void 0 !== e && ("object" != typeof e || !l(e)))
                throw new TypeError("Options should be object or undefined");
            return Object.assign({
                dkLen: 32,
                asyncTick: 10
            }, e)
        }(0, r)
          , {c: s, dkLen: f, asyncTick: a} = o;
        if (i.number(s),
        i.number(f),
        i.number(a),
        s < 1)
            throw new Error("PBKDF2: iterations (c) should be >=1");
        const c = h(e)
          , u = h(n)
          , d = new Uint8Array(f)
          , b = It.create(t, c)
          , p = b._cloneInto().update(u);
        return {
            c: s,
            dkLen: f,
            asyncTick: a,
            DK: d,
            PRF: b,
            PRFSalt: p
        }
    }
    function _t(t, e, n, r, i) {
        return t.destroy(),
        e.destroy(),
        r && r.destroy(),
        i.fill(0),
        n
    }
    const Zt = BigInt(2 ** 32 - 1)
      , Vt = BigInt(32);
    function jt(t, e=!1) {
        return e ? {
            h: Number(t & Zt),
            l: Number(t >> Vt & Zt)
        } : {
            h: 0 | Number(t >> Vt & Zt),
            l: 0 | Number(t & Zt)
        }
    }
    const zt = function(t, e=!1) {
        let n = new Uint32Array(t.length)
          , r = new Uint32Array(t.length);
        for (let i = 0; i < t.length; i++) {
            const {h: o, l: s} = jt(t[i], e);
            [n[i],r[i]] = [o, s]
        }
        return [n, r]
    }
      , Gt = (t,e,n)=>t >>> n
      , Kt = (t,e,n)=>t << 32 - n | e >>> n
      , Mt = (t,e,n)=>t >>> n | e << 32 - n
      , Wt = (t,e,n)=>t << 32 - n | e >>> n
      , Yt = (t,e,n)=>t << 64 - n | e >>> n - 32
      , Xt = (t,e,n)=>t >>> n - 32 | e << 64 - n
      , Jt = function(t, e, n, r) {
        const i = (e >>> 0) + (r >>> 0);
        return {
            h: t + n + (i / 2 ** 32 | 0) | 0,
            l: 0 | i
        }
    }
      , Qt = (t,e,n)=>(t >>> 0) + (e >>> 0) + (n >>> 0)
      , te = (t,e,n,r)=>e + n + r + (t / 2 ** 32 | 0) | 0
      , ee = (t,e,n,r)=>(t >>> 0) + (e >>> 0) + (n >>> 0) + (r >>> 0)
      , ne = (t,e,n,r,i)=>e + n + r + i + (t / 2 ** 32 | 0) | 0
      , re = (t,e,n,r,i,o)=>e + n + r + i + o + (t / 2 ** 32 | 0) | 0
      , ie = (t,e,n,r,i)=>(t >>> 0) + (e >>> 0) + (n >>> 0) + (r >>> 0) + (i >>> 0)
      , [oe,se] = zt(["0x428a2f98d728ae22", "0x7137449123ef65cd", "0xb5c0fbcfec4d3b2f", "0xe9b5dba58189dbbc", "0x3956c25bf348b538", "0x59f111f1b605d019", "0x923f82a4af194f9b", "0xab1c5ed5da6d8118", "0xd807aa98a3030242", "0x12835b0145706fbe", "0x243185be4ee4b28c", "0x550c7dc3d5ffb4e2", "0x72be5d74f27b896f", "0x80deb1fe3b1696b1", "0x9bdc06a725c71235", "0xc19bf174cf692694", "0xe49b69c19ef14ad2", "0xefbe4786384f25e3", "0x0fc19dc68b8cd5b5", "0x240ca1cc77ac9c65", "0x2de92c6f592b0275", "0x4a7484aa6ea6e483", "0x5cb0a9dcbd41fbd4", "0x76f988da831153b5", "0x983e5152ee66dfab", "0xa831c66d2db43210", "0xb00327c898fb213f", "0xbf597fc7beef0ee4", "0xc6e00bf33da88fc2", "0xd5a79147930aa725", "0x06ca6351e003826f", "0x142929670a0e6e70", "0x27b70a8546d22ffc", "0x2e1b21385c26c926", "0x4d2c6dfc5ac42aed", "0x53380d139d95b3df", "0x650a73548baf63de", "0x766a0abb3c77b2a8", "0x81c2c92e47edaee6", "0x92722c851482353b", "0xa2bfe8a14cf10364", "0xa81a664bbc423001", "0xc24b8b70d0f89791", "0xc76c51a30654be30", "0xd192e819d6ef5218", "0xd69906245565a910", "0xf40e35855771202a", "0x106aa07032bbd1b8", "0x19a4c116b8d2d0c8", "0x1e376c085141ab53", "0x2748774cdf8eeb99", "0x34b0bcb5e19b48a8", "0x391c0cb3c5c95a63", "0x4ed8aa4ae3418acb", "0x5b9cca4f7763e373", "0x682e6ff3d6b2b8a3", "0x748f82ee5defb2fc", "0x78a5636f43172f60", "0x84c87814a1f0ab72", "0x8cc702081a6439ec", "0x90befffa23631e28", "0xa4506cebde82bde9", "0xbef9a3f7b2c67915", "0xc67178f2e372532b", "0xca273eceea26619c", "0xd186b8c721c0c207", "0xeada7dd6cde0eb1e", "0xf57d4f7fee6ed178", "0x06f067aa72176fba", "0x0a637dc5a2c898a6", "0x113f9804bef90dae", "0x1b710b35131c471b", "0x28db77f523047d84", "0x32caab7b40c72493", "0x3c9ebe0a15c9bebc", "0x431d67c49c100d4c", "0x4cc5d4becb3e42b6", "0x597f299cfc657e2a", "0x5fcb6fab3ad6faec", "0x6c44198c4a475817"].map((t=>BigInt(t))))
      , fe = new Uint32Array(80)
      , ae = new Uint32Array(80);
    class ce extends p {
        constructor() {
            super(128, 64, 16, !1),
            this.Ah = 1779033703,
            this.Al = -205731576,
            this.Bh = -1150833019,
            this.Bl = -2067093701,
            this.Ch = 1013904242,
            this.Cl = -23791573,
            this.Dh = -1521486534,
            this.Dl = 1595750129,
            this.Eh = 1359893119,
            this.El = -1377402159,
            this.Fh = -1694144372,
            this.Fl = 725511199,
            this.Gh = 528734635,
            this.Gl = -79577749,
            this.Hh = 1541459225,
            this.Hl = 327033209
        }
        get() {
            const {Ah: t, Al: e, Bh: n, Bl: r, Ch: i, Cl: o, Dh: s, Dl: f, Eh: a, El: c, Fh: h, Fl: u, Gh: l, Gl: d, Hh: b, Hl: p} = this;
            return [t, e, n, r, i, o, s, f, a, c, h, u, l, d, b, p]
        }
        set(t, e, n, r, i, o, s, f, a, c, h, u, l, d, b, p) {
            this.Ah = 0 | t,
            this.Al = 0 | e,
            this.Bh = 0 | n,
            this.Bl = 0 | r,
            this.Ch = 0 | i,
            this.Cl = 0 | o,
            this.Dh = 0 | s,
            this.Dl = 0 | f,
            this.Eh = 0 | a,
            this.El = 0 | c,
            this.Fh = 0 | h,
            this.Fl = 0 | u,
            this.Gh = 0 | l,
            this.Gl = 0 | d,
            this.Hh = 0 | b,
            this.Hl = 0 | p
        }
        process(t, e) {
            for (let n = 0; n < 16; n++,
            e += 4)
                fe[n] = t.getUint32(e),
                ae[n] = t.getUint32(e += 4);
            for (let t = 16; t < 80; t++) {
                const e = 0 | fe[t - 15]
                  , n = 0 | ae[t - 15]
                  , r = Mt(e, n, 1) ^ Mt(e, n, 8) ^ Gt(e, n, 7)
                  , i = Wt(e, n, 1) ^ Wt(e, n, 8) ^ Kt(e, n, 7)
                  , o = 0 | fe[t - 2]
                  , s = 0 | ae[t - 2]
                  , f = Mt(o, s, 19) ^ Yt(o, s, 61) ^ Gt(o, s, 6)
                  , a = Wt(o, s, 19) ^ Xt(o, s, 61) ^ Kt(o, s, 6)
                  , c = ee(i, a, ae[t - 7], ae[t - 16])
                  , h = ne(c, r, f, fe[t - 7], fe[t - 16]);
                fe[t] = 0 | h,
                ae[t] = 0 | c
            }
            let {Ah: n, Al: r, Bh: i, Bl: o, Ch: s, Cl: f, Dh: a, Dl: c, Eh: h, El: u, Fh: l, Fl: d, Gh: b, Gl: p, Hh: w, Hl: g} = this;
            for (let t = 0; t < 80; t++) {
                const e = Mt(h, u, 14) ^ Mt(h, u, 18) ^ Yt(h, u, 41)
                  , y = Wt(h, u, 14) ^ Wt(h, u, 18) ^ Xt(h, u, 41)
                  , m = h & l ^ ~h & b
                  , E = ie(g, y, u & d ^ ~u & p, se[t], ae[t])
                  , x = re(E, w, e, m, oe[t], fe[t])
                  , B = 0 | E
                  , A = Mt(n, r, 28) ^ Yt(n, r, 34) ^ Yt(n, r, 39)
                  , v = Wt(n, r, 28) ^ Xt(n, r, 34) ^ Xt(n, r, 39)
                  , S = n & i ^ n & s ^ i & s
                  , I = r & o ^ r & f ^ o & f;
                w = 0 | b,
                g = 0 | p,
                b = 0 | l,
                p = 0 | d,
                l = 0 | h,
                d = 0 | u,
                ({h, l: u} = Jt(0 | a, 0 | c, 0 | x, 0 | B)),
                a = 0 | s,
                c = 0 | f,
                s = 0 | i,
                f = 0 | o,
                i = 0 | n,
                o = 0 | r;
                const O = Qt(B, v, I);
                n = te(O, x, A, S),
                r = 0 | O
            }
            ({h: n, l: r} = Jt(0 | this.Ah, 0 | this.Al, 0 | n, 0 | r)),
            ({h: i, l: o} = Jt(0 | this.Bh, 0 | this.Bl, 0 | i, 0 | o)),
            ({h: s, l: f} = Jt(0 | this.Ch, 0 | this.Cl, 0 | s, 0 | f)),
            ({h: a, l: c} = Jt(0 | this.Dh, 0 | this.Dl, 0 | a, 0 | c)),
            ({h, l: u} = Jt(0 | this.Eh, 0 | this.El, 0 | h, 0 | u)),
            ({h: l, l: d} = Jt(0 | this.Fh, 0 | this.Fl, 0 | l, 0 | d)),
            ({h: b, l: p} = Jt(0 | this.Gh, 0 | this.Gl, 0 | b, 0 | p)),
            ({h: w, l: g} = Jt(0 | this.Hh, 0 | this.Hl, 0 | w, 0 | g)),
            this.set(n, r, i, o, s, f, a, c, h, u, l, d, b, p, w, g)
        }
        roundClean() {
            fe.fill(0),
            ae.fill(0)
        }
        destroy() {
            this.buffer.fill(0),
            this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        }
    }
    class he extends ce {
        constructor() {
            super(),
            this.Ah = -1942145080,
            this.Al = 424955298,
            this.Bh = 1944164710,
            this.Bl = -1982016298,
            this.Ch = 502970286,
            this.Cl = 855612546,
            this.Dh = 1738396948,
            this.Dl = 1479516111,
            this.Eh = 258812777,
            this.El = 2077511080,
            this.Fh = 2011393907,
            this.Fl = 79989058,
            this.Gh = 1067287976,
            this.Gl = 1780299464,
            this.Hh = 286451373,
            this.Hl = -1848208735,
            this.outputLen = 28
        }
    }
    class ue extends ce {
        constructor() {
            super(),
            this.Ah = 573645204,
            this.Al = -64227540,
            this.Bh = -1621794909,
            this.Bl = -934517566,
            this.Ch = 596883563,
            this.Cl = 1867755857,
            this.Dh = -1774684391,
            this.Dl = 1497426621,
            this.Eh = -1775747358,
            this.El = -1467023389,
            this.Fh = -1101128155,
            this.Fl = 1401305490,
            this.Gh = 721525244,
            this.Gl = 746961066,
            this.Hh = 246885852,
            this.Hl = -2117784414,
            this.outputLen = 32
        }
    }
    class le extends ce {
        constructor() {
            super(),
            this.Ah = -876896931,
            this.Al = -1056596264,
            this.Bh = 1654270250,
            this.Bl = 914150663,
            this.Ch = -1856437926,
            this.Cl = 812702999,
            this.Dh = 355462360,
            this.Dl = -150054599,
            this.Eh = 1731405415,
            this.El = -4191439,
            this.Fh = -1900787065,
            this.Fl = 1750603025,
            this.Gh = -619958771,
            this.Gl = 1694076839,
            this.Hh = 1203062813,
            this.Hl = -1090891868,
            this.outputLen = 48
        }
    }
    const de = d((()=>new ce));
    d((()=>new he)),
    d((()=>new ue)),
    d((()=>new le)),
    set_secp256k1(Dt),
    set_pbkdf2((function(t, e, n, r) {
        const {c: i, dkLen: o, DK: f, PRF: a, PRFSalt: c} = $t(t, e, n, r);
        let h;
        const u = new Uint8Array(4)
          , l = s(u)
          , d = new Uint8Array(a.outputLen);
        for (let t = 1, e = 0; e < o; t++,
        e += a.outputLen) {
            const n = f.subarray(e, e + a.outputLen);
            l.setInt32(0, t, !1),
            (h = c._cloneInto(h)).update(u).digestInto(d),
            n.set(d.subarray(0, n.length));
            for (let t = 1; t < i; t++) {
                a._cloneInto(h).update(d).digestInto(d);
                for (let t = 0; t < n.length; t++)
                    n[t] ^= d[t]
            }
        }
        return _t(a, c, f, h, d)
    }
    ), de, (async function(t, e, n, r) {
        const {c: i, dkLen: o, asyncTick: f, DK: a, PRF: h, PRFSalt: u} = $t(t, e, n, r);
        let l;
        const d = new Uint8Array(4)
          , b = s(d)
          , p = new Uint8Array(h.outputLen);
        for (let t = 1, e = 0; e < o; t++,
        e += h.outputLen) {
            const n = a.subarray(e, e + h.outputLen);
            b.setInt32(0, t, !1),
            (l = u._cloneInto(l)).update(d).digestInto(p),
            n.set(p.subarray(0, n.length)),
            await c(i - 1, f, (t=>{
                h._cloneInto(l).update(p).digestInto(p);
                for (let t = 0; t < n.length; t++)
                    n[t] ^= p[t]
            }
            ))
        }
        return _t(h, u, a, l, p)
    }
    ))
}
)();
