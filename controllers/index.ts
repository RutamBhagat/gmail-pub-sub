import {
  decodeBase64ToJson,
  extractEmailData,
  getThread,
  gmail,
  isGoogleApiError,
  refreshAccessToken,
  watchInbox,
} from "./../utils/index";
import { getGlobalVar, setGlobalVar } from "../utils/file-utils";

import type { GoogleProfile } from "../types";
import type { RequestHandler } from "express";
import consola from "consola";
import { emailThreadSchema } from "../types/validations";

// Request Handlers
export const homeHandler: RequestHandler = (req, res) => {
  res.send({ authenticated: !!req.user, user: req.user });
};

export const authCallbackHandler: RequestHandler = (req, res) => {
  if (req.user && "accessToken" in req.user && "refreshToken" in req.user) {
    const user = req.user as GoogleProfile;
    setGlobalVar("accessTokenStore", user.accessToken || "");
    setGlobalVar("refreshTokenStore", user.refreshToken || "");
  }
  res.redirect("/");
};

export const startWatchingHandler: RequestHandler = async (req, res) => {
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

export const webhookHandler: RequestHandler = async (req, res) => {
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

      const validationResult = emailThreadSchema.safeParse(threadData);
      if (!validationResult.success) {
        const errors = validationResult.error.errors
          .map((e) => e.message)
          .join(",");
        res.status(400).json(errors);
        return;
      }

      setGlobalVar("threadData", threadData);
      consola.log("Thread Data:", JSON.stringify(threadData, null, 2));
      const emailThread = validationResult.data.messages;
      const extractedData = extractEmailData(emailThread);
      res.status(200).json(extractedData);
      return;
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

export const healthCheckHandler: RequestHandler = (req, res) => {
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
