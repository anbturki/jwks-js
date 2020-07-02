import fetch from "isomorphic-unfetch";
export default class JwkClient {
  constructor(jwksUri) {
    this.jwksUri = jwksUri;
  }

  async getSigningKey(kid) {
    try {
      const keys = await this.getSigningKeys();

      const key = keys.find((k) => k.kid === kid);
      if (key) {
        return Promise.resolve(key);
      }
      return Promise.reject(
        "Unable to find a signing key that matches '" + kid + "'"
      );
    } catch (error) {
      return Promise.reject(error);
    }
  }

  async getSigningKeys() {
    const self = this;
    try {
      const keys = await this.__requestKeys();
      if (!keys || !keys.length) {
        return Promise.reject("The JWKS endpoint did not contain any keys");
      }

      const signingKeys = keys
        .filter(function (key) {
          return (
            key.use === "sig" &&
            key.kty === "RSA" &&
            key.kid &&
            ((key.x5c && key.x5c.length) || (key.n && key.e))
          );
        })
        .map(function (key) {
          if (key.x5c && key.x5c.length) {
            return {
              kid: key.kid,
              nbf: key.nbf,
              publicKey: self.__certToPEM(key.x5c[0]),
            };
          } else {
            return {
              kid: key.kid,
              nbf: key.nbf,
              rsaPublicKey: self.__rsaPublicKeyToPEM(key.n, key.e),
            };
          }
        });

      if (!signingKeys.length) {
        return Promise.reject(
          "The JWKS endpoint did not contain any signing keys"
        );
      }
      return Promise.resolve(signingKeys);
    } catch (error) {
      return Promise.reject(error);
    }
  }
  __certToPEM(cert) {
    cert = cert.match(/.{1,64}/g).join("\n");
    cert =
      "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----\n";
    return cert;
  }

  __prepadSigned(hexStr) {
    var msb = hexStr[0];
    if (msb < "0" || msb > "7") {
      return "00" + hexStr;
    }
    return hexStr;
  }

  __rsaPublicKeyToPEM(modulusB64, exponentB64) {
    var modulus = new Buffer(modulusB64, "base64");
    var exponent = new Buffer(exponentB64, "base64");
    var modulusHex = this.__prepadSigned(modulus.toString("hex"));
    var exponentHex = this.__prepadSigned(exponent.toString("hex"));
    var modlen = modulusHex.length / 2;
    var explen = exponentHex.length / 2;

    var encodedModlen = this.__encodeLengthHex(modlen);
    var encodedExplen = this.__encodeLengthHex(explen);
    var encodedPubkey =
      "30" +
      this.__encodeLengthHex(
        modlen +
          explen +
          encodedModlen.length / 2 +
          encodedExplen.length / 2 +
          2
      ) +
      "02" +
      encodedModlen +
      modulusHex +
      "02" +
      encodedExplen +
      exponentHex;

    var der = new Buffer(encodedPubkey, "hex").toString("base64");

    var pem = "-----BEGIN RSA PUBLIC KEY-----\n";
    pem += "" + der.match(/.{1,64}/g).join("\n");
    pem += "\n-----END RSA PUBLIC KEY-----\n";
    return pem;
  }

  async __requestKeys() {
    try {
      const response = await fetch(this.jwksUri);
      const body = await response.json();
      return Promise.resolve(body.keys);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  __toHex(number) {
    var nstr = number.toString(16);
    if (nstr.length % 2) {
      return "0" + nstr;
    }
    return nstr;
  }

  __encodeLengthHex(n) {
    if (n <= 127) {
      return this.__toHex(n);
    }
    var nHex = this.__toHex(n);
    var lengthOfLengthByte = 128 + nHex.length / 2;
    return this.__toHex(lengthOfLengthByte) + nHex;
  }
}
