import "dotenv/config";

import { type RequestHandler } from "express";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import consola from "consola";
import express from "express";
import { google } from "googleapis";
import passport from "passport";
import session from "express-session";

/**
 * Represents a user's data structure returned from Google OAuth
 */
interface User {
  id?: string;
  displayName?: string;
  emails?: { value: string; verified?: boolean }[];
}

/**
 * Data structure for Gmail push notification payloads
 * @property {string} emailAddress - The email address receiving the notification
 * @property {string} historyId - Gmail's history ID for tracking changes
 */
interface GmailNotificationData {
  emailAddress: string;
  historyId: string;
}

interface GoogleProfile extends User {
  accessToken?: string;
  refreshToken?: string;
}

declare module "http" {
  interface IncomingMessage {
    rawBody?: Buffer;
  }
}

declare module "express-session" {
  interface SessionData {
    user?: GoogleProfile;
  }
}

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL!;
const SESSION_SECRET = process.env.SESSION_SECRET || "keyboard cat";
const GMAIL_TOPIC_NAME =
  process.env.GMAIL_TOPIC_NAME ||
  "projects/YOUR_PROJECT_ID/topics/YOUR_TOPIC_NAME";

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

const gmail = google.gmail("v1");

let accessTokenStore: string = "";
let historyId: string = "";
let emailAddress: string = "";
let threadId: string = "";
let messageDetails = {};

/**
 * Google OAuth Strategy configuration
 * Handles the OAuth flow and user profile creation
 * @param {string} accessToken - OAuth access token from Google
 * @param {string} refreshToken - OAuth refresh token from Google
 * @param {object} profile - User profile data from Google
 * @param {Function} done - Passport.js callback function
 */
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
  (req, res) => {
    if (req.user && "accessToken" in req.user) {
      accessTokenStore = (req.user as GoogleProfile).accessToken || "";
    }
    res.redirect("/");
  }
);

app.get("/", (req, res) => {
  res.send({ authenticated: !!req.user, user: req.user });
});

/**
 * Initiates Gmail push notifications for the authenticated user's inbox.
 * Sets up a watch on the inbox using Gmail API and stores the historyId
 * for tracking changes.
 */
const watchInbox = async () => {
  try {
    const res = await gmail.users.watch(
      {
        userId: "me",
        requestBody: {
          labelIds: ["INBOX"],
          topicName: GMAIL_TOPIC_NAME,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${accessTokenStore}`,
        },
      }
    );
    consola.success("Watching Inbox:", res.data);
    if (res.data.historyId) {
      historyId = res.data.historyId;
    }
  } catch (error) {
    consola.error("Error watching inbox:", error);
  }
};

/**
 * Retrieves the most recent message from the user's Gmail inbox.
 * @returns {Promise<string|null>} The ID of the most recent message or null if no messages found
 */
const listMessages = async (): Promise<string | null> => {
  try {
    const res = await gmail.users.messages.list(
      {
        userId: "me",
        q: "is:inbox",
        maxResults: 1,
      },
      {
        headers: {
          Authorization: `Bearer ${accessTokenStore}`,
        },
      }
    );
    consola.success("Listed Messages:", res.data);
    if (res.data.messages && res.data.messages.length > 0) {
      const lastMessageId = res.data.messages[0].id;
      consola.info("Last Message ID:", lastMessageId);
      return lastMessageId ?? null;
    } else {
      consola.warn("No messages found in the inbox.");
      return null;
    }
  } catch (error) {
    consola.error("Error listing messages:", error);
    return null;
  }
};

/**
 * Fetches detailed information about a specific Gmail message.
 * @param messageId - The unique identifier of the Gmail message
 * @returns {Promise<object|null>} The message details or null if retrieval fails
 */
const getMessageDetails = async (messageId: string): Promise<object | null> => {
  try {
    const res = await gmail.users.messages.get(
      {
        userId: "me",
        id: messageId,
      },
      {
        headers: {
          Authorization: `Bearer ${accessTokenStore}`,
        },
      }
    );
    messageDetails = res.data;
    consola.success("Fetched Message Details:", res.data);
    return res.data;
  } catch (error) {
    consola.error("Error getting message details:", error);
    return null;
  }
};

/**
 * Gmail webhook endpoint handler
 * Processes incoming Gmail push notifications:
 * 1. Validates the incoming message data
 * 2. Decodes the base64 encoded payload
 * 3. Updates email tracking information
 * 4. Fetches new message details if available
 */
app.post("/webhook/gmail", async (req, res) => {
  try {
    consola.info("Gmail Webhook Received");
    res.status(200).send("ok");

    const { message } = req.body;
    if (!message?.data) {
      consola.warn("No message data found");
      return;
    }

    const decodedData = decodeBase64ToJson(message.data);
    if (!decodedData || !decodedData.emailAddress || !decodedData.historyId) {
      consola.warn("Decoded message is missing emailAddress or historyId.");
      return;
    }

    emailAddress = decodedData.emailAddress;
    historyId = decodedData.historyId;
    consola.info("Decoded JSON Message:", decodedData);

    const messageId = await listMessages();

    if (messageId) {
      const messageDetails = await getMessageDetails(messageId);
      consola.log("Message Details: ", messageDetails);
    }
  } catch (error) {
    consola.error("Error in webhook handler:", error);
  }
});

/**
 * Request handler for initiating Gmail inbox watching
 * Validates user authentication and starts the Gmail push notification subscription
 * @throws {Error} If user is not authenticated or watch operation fails
 */
const startWatchingHandler: RequestHandler = async (req, res) => {
  try {
    if (!req.user || !accessTokenStore) {
      res
        .status(401)
        .send("User not authenticated or access token not available.");
      return;
    }
    await watchInbox();
    res.send("Started watching inbox");
  } catch (error) {
    consola.error("Error starting watch:", error);
    res.status(500).send("Failed to start watching inbox");
  }
};

app.get("/start-watching", startWatchingHandler);

// Health check endpoint supporting GET and HEAD
app
  .route("/health")
  .get((req, res) => {
    // Log request details
    console.log({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      headers: {
        userAgent: req.get("user-agent"),
        correlationId: req.get("x-correlation-id"),
        host: req.get("host"),
      },
      ip: req.ip,
    });

    res.status(200).json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || "1.0.0",
    });
  })
  .head((req, res) => {
    // Log request details
    console.log({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      headers: {
        userAgent: req.get("user-agent"),
        correlationId: req.get("x-correlation-id"),
        host: req.get("host"),
      },
      ip: req.ip,
    });

    res.status(200).end();
  });

app
  .listen(PORT, "0.0.0.0", () => {
    consola.success(`Server is running on http://0.0.0.0:${PORT}`);
  })
  .on("error", (err) => {
    consola.error("Server failed to start:", err);
    process.exit(1);
  });

/**
 * Base64 decoder utility for Gmail push notification payloads
 * Handles the decoding and JSON parsing of Gmail's base64 encoded messages
 * @param {string|object} encodedString - Base64 encoded string to decode
 * @returns {GmailNotificationData|null} Decoded notification data or null if decoding fails
 * @throws {Error} If JSON parsing fails
 */
function decodeBase64ToJson(
  encodedString:
    | WithImplicitCoercion<string>
    | { [Symbol.toPrimitive](hint: "string"): string }
): GmailNotificationData | null {
  try {
    const decodedString = Buffer.from(encodedString, "base64").toString(
      "utf-8"
    );
    return JSON.parse(decodedString);
  } catch (error) {
    consola.error("Error decoding base64 to JSON:", error);
    return null;
  }
}
