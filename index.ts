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
import type {
  GmailNotificationData,
  GoogleApiError,
  GoogleProfile,
  User,
} from "./types";

// Constants
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL!;
const SESSION_SECRET = process.env.SESSION_SECRET || "keyboard cat";
const GMAIL_TOPIC_NAME =
  process.env.GMAIL_TOPIC_NAME ||
  "projects/YOUR_PROJECT_ID/topics/YOUR_TOPIC_NAME";

// App & Middleware Setup
const app = express();
const gmail = google.gmail("v1");

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

// Utility Functions
/**
 * Decodes and parses Gmail push notification payload from base64
 * @param encodedString - Base64 encoded notification data
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

/**
 * Refreshes the Google OAuth access token using the stored refresh token
 */
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

const isGoogleApiError = (error: unknown): error is GoogleApiError => {
  return (
    typeof error === "object" &&
    error !== null &&
    "response" in error &&
    typeof (error as any).response?.status === "number"
  );
};

// Gmail API Functions
/**
 * Initiates Gmail push notifications subscription
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
 * Fetches an email thread by its ID with token refresh handling
 */
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
const homeHandler: RequestHandler = (req, res) => {
  res.send({ authenticated: !!req.user, user: req.user });
};

const authCallbackHandler: RequestHandler = (req, res) => {
  if (req.user && "accessToken" in req.user && "refreshToken" in req.user) {
    const user = req.user as GoogleProfile;
    setGlobalVar("accessTokenStore", user.accessToken || "");
    setGlobalVar("refreshTokenStore", user.refreshToken || "");
  }
  res.redirect("/");
};

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
      setGlobalVar("threadId", threadId);

      const threadData = await getThread(threadId);
      if (!threadData) {
        res.status(404).send("Thread not found");
        return;
      }

      setGlobalVar("threadData", threadData);
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

        setGlobalVar("threadData", threadData);
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

const healthCheckHandler: RequestHandler = (req, res) => {
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
};

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
