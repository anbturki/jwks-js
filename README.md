# jwks-js

## Usage Example

```js
import JwkClient from "jwks-js";
import jwt from "jsonwebtoken";

const oAuthDomain = process.env.AUTH_DOMAIN;
const url = `${oAuthDomain}/.well-known/jwks.json`;
const client = new JwkClient(url);

function getKey(header, callback) {
  client
    .getSigningKey(header.kid)
    .then((key) => {
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    })
    .catch((error) => {
      callback(error, null);
    });
}

// Verify the access_token by comparing the RSA with the token
function verifyToken(token) {
  if (!token) {
    return Promise.reject("token undefined");
  }
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, function (err, decoded) {
      if (err) return reject(err);
      return resolve(decoded);
    });
  });
}
```
