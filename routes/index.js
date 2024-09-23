const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const router = express.Router();

// Use environment variables for sensitive file paths
const privateKeyPath =
  process.env.PRIVATE_KEY_PATH || "./public/certificates/private_key.pem";
const publicKeyPath =
  process.env.PUBLIC_KEY_PATH || "./public/certificates/public_key.pem";

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

// Input validation
function validateIput(input) {
  if (typeof input !== "string" || input.trim() === "") {
    throw new Error("Invalid input: Input must be a non-empty string");
  }
}

// Error handling middleware for safe responses
function handleErrors(err, req, res, next) {
  console.log(err.stack);
  res.status(500).send({
    message: "An internal error occured",
  });
}

// Signing route
router.post("/sign", (req, res, next) => {
  try {
    let data = req.body.data;

    // validate input
    validateIput(data);

    // Read the private key from the file system
    const privateKey = fs.readFileSync(privateKeyPath, "utf8");

    // Create the sign object
    const sign = crypto.createSign("SHA256");
    sign.update(data);
    sign.end();

    // Sign the data using the private key
    const signature = sign.sign(privateKey).toString("base64");

    res.send({ data, signature });
  } catch (err) {
    next(err); // Pass errors to the error handler
  }
});

router.post("/verify", (req, res, next) => {
  try {
    let { data, signature } = req.body;

    // Read the public key from the PEM file
    const publicKeyPem = fs.readFileSync(publicKeyPath, "utf8");

    // Create a public key object using the PEM certificate
    const publicKey = crypto.createPublicKey(publicKeyPem);

    // Create the verify object
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    verify.end();

    // Verify the signature using the public key
    const isVerified = verify.verify(
      publicKey,
      Buffer.from(signature, "base64")
    );

    res.send({ verify: isVerified });
  } catch (err) {
    next(err);
  }
});
module.exports = router;
