const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");

console.log("ESTE ES EL SERVER CORRECTO ");

const app = express();

app.use(cors());
app.use(express.json());

//  Servir carpeta public correctamente usando path absoluto
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "index.html"));
});

//  Generar par de llaves
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Endpoint llave pública
app.get("/api/public-key", (req, res) => {
  console.log(" Enviando llave pública");
  res.json({ publicKey });
});

// Endpoint mensaje seguro
app.post("/api/secure-message", (req, res) => {
  try {
    console.log(" Payload recibido");

    const { encryptedMessage, encryptedKey, iv } = req.body;

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encryptedKey, "base64")
    );

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      aesKey,
      Buffer.from(iv, "base64")
    );

    let decrypted = decipher.update(
      Buffer.from(encryptedMessage, "base64")
    );
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    console.log(" Mensaje descifrado:", decrypted.toString());

    res.json({ 
  status: "ok",
  decryptedMessage: decrypted.toString()
});
  } catch (error) {
    console.error(" Error:", error.message);
    res.status(500).json({ error: "Error al descifrar" });
  }
});

app.listen(3000, () => {
  console.log(" Servidor corriendo en http://localhost:3000");
});