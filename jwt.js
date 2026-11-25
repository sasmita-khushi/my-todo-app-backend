import crypto from "crypto";
import "dotenv/config";

export function createJWT(payload, secretKey, expiresInSecond) {
  let header = {
    alg: "HS256",
    typ: "JWT",
  };

  if (expiresInSecond) {
    let currentTimeInSecond = Math.floor(Date.now() / 1000);

    payload.exp = currentTimeInSecond + parseInt(expiresInSecond);

    let encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      "base64url",
    );
    let encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      "base64url",
    );

    let tokenData = `${encodedHeader}.${encodedPayload}`;

    let signature = crypto
      .createHmac("sha256", secretKey)
      .update(tokenData)
      .digest("base64url");
    let finalJwt = `${tokenData}.${signature}`;
    return finalJwt;
  } else {
    throw new Error("Missing Expiry Time");
  }
}

export function verifyJWT(token, secretKey) {
  let [encodedHeader, encodedPayload, signature] = token.split(".");

  if (!encodedHeader || !encodedPayload || !signature) {
    return false;
  }

  let newSignature = crypto
    .createHmac("sha256", secretKey)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");

  if (newSignature === signature) {
    let decodedPayloadString = Buffer.from(
      encodedPayload,
      "base64url",
    ).toString();
    let decodedPayload;

    try {
      decodedPayload = JSON.parse(decodedPayloadString);
    } catch (err) {
      return false;
    }

    if (decodedPayload.exp) {
      const currentTimestampInSeconds = Math.floor(Date.now() / 1000);

      if (currentTimestampInSeconds < decodedPayload.exp) {
        return decodedPayload;
      } else {
        return false;
      }
    } else {
      return false;
    }
  } else {
    return false;
  }
}

export function createAccessToken(payload) {
  const secret = process.env.ACCESS_TOKEN_KEY;
  const expiryTime = process.env.ACCESS_TOKEN_EXPIRY;

  if (!secret || !expiryTime) {
    throw new Error("Missing access token configuration in .env");
  }

  return createJWT(payload, secret, Number(expiryTime));
}

export function createRefreshToken(payload) {
  const secret = process.env.REFRESH_TOKEN_KEY;
  const expiryTime = process.env.REFRESH_TOKEN_EXPIRY;

  if (!secret || !expiryTime) {
    throw new Error("Missing refresh token configuration in .env");
  }

  return createJWT(payload, secret, Number(expiryTime));
}
