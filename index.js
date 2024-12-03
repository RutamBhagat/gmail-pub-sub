import "dotenv/config";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import express from "express";
import passport from "passport";
import session from "express-session";

const PORT = process.env.PORT;
const app = express();

/**
 * Configure body-parser middleware to handle JSON payloads up to 50mb
 * Stores raw body buffer for webhook verification
 */
app.use(
  bodyParser.json({
    limit: "50mb",
    verify: (req, _, buf) => {
      req.rawBody = buf;
    },
  })
);

/**
 * Initialize session middleware for maintaining user sessions
 * Uses SESSION_SECRET from environment variables for security
 */
app.use(
  session({
    secret: process.env.SESSION_SECRET || "keyboard cat",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(
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

// Add passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

/**
 * Google OAuth authentication route
 * Initiates the Google OAuth2 authentication flow
 * Requests access to user profile, email, and Gmail API permissions
 */
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.labels",
    ],
  })
);

/**
 * Google OAuth callback route
 * Handles the OAuth2 callback from Google
 * Redirects to home page on successful authentication
 */
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/");
  }
);

/**
 * Home route
 * Returns the authentication status and user data if authenticated
 */
app.get("/", (req, res) => {
  if (req.user) {
    res.send({ authenticated: true, user: req.user });
  } else {
    res.send({ authenticated: false });
  }
});

/**
 * Gmail webhook endpoint
 * Handles incoming push notifications from Gmail
 * Processes base64 encoded message data and attempts to decode JSON payloads
 */
app.post("/webhook/gmail", (req, res) => {
  console.log("Gmail Webhook Received");
  res.status(200).send("ok");

  console.log("Received body:", req.body);

  const { message } = req.body;

  if (!message || !message.data) {
    console.log("No message data found");
    return;
  }

  try {
    // Decode the Base64 encoded message data
    const encodedMessage = message.data;
    const decodedString = Buffer.from(encodedMessage, "base64").toString(
      "utf-8"
    );
    console.log("Decoded string:", decodedString);

    // Only try to parse as JSON if the string looks like JSON
    if (decodedString.startsWith("{") || decodedString.startsWith("[")) {
      const decodedMessage = JSON.parse(decodedString);
      console.log("Decoded JSON Message:", decodedMessage);
    } else {
      console.log("Decoded message is not JSON");
    }
  } catch (error) {
    console.error("Error processing message:", error);
  }
});

const host = "0.0.0.0";
app
  .listen(PORT, host, () => {
    console.log(`Server is running on http://${host}:${PORT}`);
  })
  .on("error", (err) => {
    console.error("Server failed to start:", err);
    process.exit(1);
  });
