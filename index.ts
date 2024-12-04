import "dotenv/config";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import consola from "consola";
import express from "express";
import { google } from "googleapis";
import passport from "passport";
import session from "express-session";

interface User {
  id?: string;
  displayName?: string;
  emails?: { value: string; verified?: boolean }[];
}

interface GmailNotificationData {
  emailAddress: string;
  historyId: string;
}

declare module "http" {
  interface IncomingMessage {
    rawBody?: Buffer;
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

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      consola.info("Access Token: ", accessToken);
      consola.info("Refresh Token: ", refreshToken);
      consola.info("Profile: ", profile);
      passport.serializeUser((user: Express.User, done) => done(null, user));
      passport.deserializeUser((user: User, done) => done(null, user));
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
  (req, res) => res.redirect("/")
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

app.post("/webhook/gmail", async (req, res) => {
  consola.info("Gmail Webhook Received");
  res.status(200).send("ok");

  const { message } = req.body;
  if (!message || !message.data) {
    consola.warn("No message data found");
    return;
  }

  try {
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
    consola.error("Error processing message:", error);
  }
});

app.get("/start-watching", (req, res) => {
  if (req.user && accessTokenStore) {
    watchInbox();
    res.send("Started watching inbox");
  } else {
    res
      .status(401)
      .send("User not authenticated or access token not available.");
  }
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
 * Decodes a base64 encoded string into a JSON object.
 * Used for processing Gmail push notification payloads.
 * @param encodedString - The base64 encoded string to decode
 * @returns {object|null} The decoded JSON object or null if decoding fails
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
