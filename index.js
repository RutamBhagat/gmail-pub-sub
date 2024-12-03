require("dotenv").config();

import { authenticate, initialize, use } from "passport";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import express from "express";
import { json } from "body-parser";

const PORT = process.env.PORT;
const app = express();

app.use(
  json({
    limit: "50mb",
    verify: (req, _, buf) => {
      req.rawBody = buf;
    },
  })
);

app.use(initialize());

use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      console.log("Access Token: ", accessToken);
      console.log("Refresh Token: ", refreshToken);
      console.log("Profile: ", profile);
      done(null, profile);
    }
  )
);

app.get(
  "/auth/google",
  authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.labels",
    ],
  })
);

app.get(
  "/auth/google/callback",
  authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/");
  }
);

app.get("/", (req, res) => {
  console.log("User: ", req.user);
});

app.post("/webhook/gmail", (req, res) => {
  console.log("Gmail Webhook Received");
  res.status(200).send("ok");

  console.log(req.body);

  const { message } = req.body;

  if (!message || !message.data) {
    console.log("No message data found");
    return;
  }

  // Decode the Base64 encoded message data
  const encodedMessage = message.data;
  const decodedMessage = JSON.parse(
    Buffer.from(encodedMessage, "base64").toString("utf-8")
  );
  console.log("Decoded Message: ", decodedMessage);
});

app.listen(PORT, () => {
  console.log("Server is running on port", PORT);
});
