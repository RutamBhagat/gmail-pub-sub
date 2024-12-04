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

declare module "http" {
  interface IncomingMessage {
    rawBody?: Buffer;
  }
}

// --- Configuration ---
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL!;
const SESSION_SECRET = process.env.SESSION_SECRET || "keyboard cat"; // Use a strong secret in production
const GMAIL_TOPIC_NAME =
  process.env.GMAIL_TOPIC_NAME ||
  "projects/YOUR_PROJECT_ID/topics/YOUR_TOPIC_NAME"; // Replace with your actual topic name
// --- End of Configuration ---

const app = express();

// --- Middleware ---
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

// --- Gmail API Setup ---
const gmail = google.gmail("v1");

// --- In-Memory Storage --- (For simplicity – reconsider for production)
let accessTokenStore: string = "";
let historyId: string = "";
let emailAddress: string = "";
let threadId: string = "";
let messageDetails = {};

// --- Passport.js Configuration ---
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      consola.info("Access Token: ", accessToken); // Log with consola
      consola.info("Refresh Token: ", refreshToken);
      consola.info("Profile: ", profile);
      passport.serializeUser((user: Express.User, done) => done(null, user));
      passport.deserializeUser((user: User, done) => done(null, user));
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user: unknown, done) => done(null, user as User));

// --- Routes ---
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

// --- Gmail API Interaction Functions ---
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
      historyId = res.data.historyId; // Store historyId
    }
  } catch (error) {
    consola.error("Error watching inbox:", error);
  }
};

const listMessages = async () => {
  try {
    const res = await gmail.users.messages.list(
      {
        userId: "me",
        q: "is:inbox",
        maxResults: 1, // Get the most recent message
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
      return lastMessageId;
    } else {
      consola.warn("No messages found in the inbox.");
      return null;
    }
  } catch (error) {
    consola.error("Error listing messages:", error);
    return null;
  }
};

const getMessageDetails = async (messageId: string) => {
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
    messageDetails = res.data; // Store the entire message details
    consola.success("Fetched Message Details:", res.data);
    return res.data;
  } catch (error) {
    consola.error("Error getting message details:", error);
    return null;
  }
};

// --- Webhook and Subsequent Actions ---
app.post("/webhook/gmail", async (req, res) => {
  consola.info("Gmail Webhook Received"); // Improved logging
  res.status(200).send("ok");

  const { message } = req.body;
  if (!message || !message.data) {
    consola.warn("No message data found"); // Improved logging
    return;
  }

  try {
    const decodedData = decodeBase64ToJson(message.data);
    if (!decodedData || !decodedData.emailAddress || !decodedData.historyId) {
      consola.warn("Decoded message is missing emailAddress or historyId.");
      return; // Stop processing if these are missing
    }

    emailAddress = decodedData.emailAddress;
    historyId = decodedData.historyId; // Update historyId
    consola.info("Decoded JSON Message:", decodedData);

    const messageId = await listMessages();

    if (messageId) {
      const messageDetails = await getMessageDetails(messageId);
      consola.log("Message Details: ", messageDetails);
    }
  } catch (error) {
    consola.error("Error processing message:", error); // Improved logging
  }
});

// --- Start Watching Inbox After Authentication ---
// This ensures watchInbox is called after a user is authenticated and we have an access token.
app.get("/start-watching", (req, res) => {
  if (req.user && accessTokenStore) {
    watchInbox(); // Call watchInbox when the user is logged in.
    res.send("Started watching inbox");
  } else {
    res
      .status(401)
      .send("User not authenticated or access token not available.");
  }
});

// --- Start Server ---
app
  .listen(PORT, "0.0.0.0", () => {
    consola.success(`Server is running on http://0.0.0.0:${PORT}`); // Use consola
  })
  .on("error", (err) => {
    consola.error("Server failed to start:", err); // Use consola
    process.exit(1);
  });

// Helper function
function decodeBase64ToJson(
  encodedString:
    | WithImplicitCoercion<string>
    | { [Symbol.toPrimitive](hint: "string"): string }
) {
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
