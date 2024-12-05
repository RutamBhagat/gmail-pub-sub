import "dotenv/config";

import {
  GOOGLE_CALLBACK_URL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  PORT,
  SESSION_SECRET,
} from "./consts";
import type { GoogleProfile, User } from "./types";
import {
  authCallbackHandler,
  healthCheckHandler,
  homeHandler,
  startWatchingHandler,
  webhookHandler,
} from "./controllers";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import consola from "consola";
import express from "express";
import passport from "passport";
import session from "express-session";

// App & Middleware Setup
const app = express();

app.use(
  bodyParser.json({
    limit: "50mb",
    verify: (req, _, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(
  session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport Configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      const user: GoogleProfile = {
        id: profile.id,
        displayName: profile.displayName,
        emails: profile.emails,
        accessToken,
        refreshToken,
      };
      done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user: unknown, done) => done(null, user as User));

// Routes
app.get("/", homeHandler);
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
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  authCallbackHandler
);
app.get("/start-watching", startWatchingHandler);
app.post("/webhook/gmail", webhookHandler);
app.route("/health").get(healthCheckHandler).head(healthCheckHandler);

// Server Initialization
app
  .listen(PORT, "0.0.0.0", () => {
    consola.success(`Server is running on http://0.0.0.0:${PORT}`);
  })
  .on("error", (err) => {
    consola.error("Server failed to start:", err);
    process.exit(1);
  });
