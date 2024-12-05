import "dotenv/config";

import { type RequestHandler } from "express";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import consola from "consola";
import express from "express";
import { google } from "googleapis";
import passport from "passport";
import session from "express-session";
import { getGlobalVar, setGlobalVar } from "./file-utils";

// Constants and Configuration
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL!;
const SESSION_SECRET = process.env.SESSION_SECRET || "keyboard cat";
const GMAIL_TOPIC_NAME =
  process.env.GMAIL_TOPIC_NAME ||
  "projects/YOUR_PROJECT_ID/topics/YOUR_TOPIC_NAME";

// Type Definitions and Interfaces
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

interface GoogleApiError {
  response?: {
    status: number;
  };
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

// App and Middleware Configuration
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

// Google APIs and Services Initialization
const gmail = google.gmail("v1");

// Passport Google OAuth Strategy Configuration
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

// Utility Functions
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

// Add this new utility function
const refreshAccessToken = async (): Promise<string> => {
  try {
    const oauth2Client = new google.auth.OAuth2(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      GOOGLE_CALLBACK_URL
    );

    oauth2Client.setCredentials({
      refresh_token: getGlobalVar("refreshTokenStore"),
    });

    const { credentials } = await oauth2Client.refreshAccessToken();
    setGlobalVar("accessTokenStore", credentials.access_token || "");
    return getGlobalVar("accessTokenStore");
  } catch (error) {
    consola.error("Error refreshing access token:", error);
    throw error;
  }
};

function isGoogleApiError(error: unknown): error is GoogleApiError {
  return (
    typeof error === "object" &&
    error !== null &&
    "response" in error &&
    typeof (error as any).response?.status === "number"
  );
}

// Gmail API Interaction Functions
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
          Authorization: `Bearer ${getGlobalVar("accessTokenStore")}`,
        },
      }
    );
    consola.success("Watching Inbox:", res.data);
    if (res.data.historyId) {
      setGlobalVar("historyId", res.data.historyId);
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
    try {
      // Try with current access token first
      try {
        const res = await gmail.users.messages.list(
          {
            userId: "me",
            q: "is:inbox",
            maxResults: 1,
          },
          {
            headers: {
              Authorization: `Bearer ${getGlobalVar("accessTokenStore")}`,
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
      } catch (error: unknown) {
        if (isGoogleApiError(error) && error.response?.status === 401) {
          const newToken = await refreshAccessToken();
          const res = await gmail.users.messages.list(
            {
              userId: "me",
              q: "is:inbox",
              maxResults: 1,
            },
            {
              headers: {
                Authorization: `Bearer ${newToken}`,
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
        } else {
          throw error;
        }
      }
    } catch (error) {
      consola.error("Error listing messages:", error);
      return null;
    }
  } catch (error) {
    consola.error("Error listing messages:", error);
    return null;
  }
};

// Add this after the getMessageDetails function
const getThread = async (threadId: string): Promise<object | null> => {
  try {
    try {
      const res = await gmail.users.threads.get(
        {
          userId: "me",
          id: threadId,
        },
        {
          headers: {
            Authorization: `Bearer ${getGlobalVar("accessTokenStore")}`,
          },
        }
      );
      return res.data;
    } catch (error: unknown) {
      if (isGoogleApiError(error) && error.response?.status === 401) {
        const newToken = await refreshAccessToken();
        const res = await gmail.users.threads.get(
          {
            userId: "me",
            id: threadId,
          },
          {
            headers: {
              Authorization: `Bearer ${newToken}`,
            },
          }
        );
        return res.data;
      }
      throw error;
    }
  } catch (error) {
    consola.error("Error getting thread:", error);
    return null;
  }
};

// Request Handlers
/**
 * Request handler for initiating Gmail inbox watching
 * Validates user authentication and starts the Gmail push notification subscription
 * @throws {Error} If user is not authenticated or watch operation fails
 */
const startWatchingHandler: RequestHandler = async (req, res) => {
  try {
    if (!req.user || !getGlobalVar("accessTokenStore")) {
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

// Replace the two webhook handlers with this single correctly typed version
const webhookHandler: RequestHandler = async (req, res) => {
  try {
    consola.info("Gmail Webhook Received");

    const { message } = req.body;
    if (!message?.data) {
      consola.warn("No message data found");
      res.status(400).send("No message data");
      return;
    }

    const decodedData = decodeBase64ToJson(message.data);
    if (!decodedData || !decodedData.emailAddress || !decodedData.historyId) {
      consola.warn("Decoded message is missing emailAddress or historyId.");
      res.status(400).send("Invalid message format");
      return;
    }

    setGlobalVar("emailAddress", decodedData.emailAddress);
    setGlobalVar("historyId", decodedData.historyId);
    consola.info("Decoded JSON Message:", decodedData);

    try {
      const messagesResponse = await gmail.users.messages.list(
        {
          userId: "me",
          q: "is:inbox",
          maxResults: 1,
        },
        {
          headers: {
            Authorization: `Bearer ${getGlobalVar("accessTokenStore")}`,
          },
        }
      );

      if (!messagesResponse.data.messages?.[0]?.threadId) {
        res.status(404).send("No thread found");
        return;
      }

      const threadId = messagesResponse.data.messages[0].threadId;
      const threadData = await getThread(threadId);
      if (!threadData) {
        res.status(404).send("Thread not found");
        return;
      }

      consola.log("Thread Data:", JSON.stringify(threadData, null, 2));
      res.status(200).json(threadData);
    } catch (error: unknown) {
      if (isGoogleApiError(error) && error.response?.status === 401) {
        const newToken = await refreshAccessToken();
        const messagesResponse = await gmail.users.messages.list(
          {
            userId: "me",
            q: "is:inbox",
            maxResults: 1,
          },
          {
            headers: {
              Authorization: `Bearer ${newToken}`,
            },
          }
        );

        if (!messagesResponse.data.messages?.[0]?.threadId) {
          res.status(404).send("No thread found");
          return;
        }

        const threadId = messagesResponse.data.messages[0].threadId;
        const threadData = await getThread(threadId);
        if (!threadData) {
          res.status(404).send("Thread not found");
          return;
        }

        consola.log("Thread Data:", JSON.stringify(threadData, null, 2));
        res.status(200).json(threadData);
        return;
      }
      throw error;
    }
  } catch (error) {
    consola.error("Error in webhook handler:", error);
    res.status(500).send("Error processing Gmail notification");
  }
};

// Register the webhook route
app.post("/webhook/gmail", webhookHandler);

// Route Definitions
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
    if (req.user && "accessToken" in req.user && "refreshToken" in req.user) {
      const user = req.user as GoogleProfile;
      setGlobalVar("accessTokenStore", user.accessToken || "");
      setGlobalVar("refreshTokenStore", user.refreshToken || "");
    }
    res.redirect("/");
  }
);

app.get("/", (req, res) => {
  res.send({ authenticated: !!req.user, user: req.user });
});

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

// Server Initialization
app
  .listen(PORT, "0.0.0.0", () => {
    consola.success(`Server is running on http://0.0.0.0:${PORT}`);
  })
  .on("error", (err) => {
    consola.error("Server failed to start:", err);
    process.exit(1);
  });
