import {
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
import axios from "axios";
import consola from "consola";
import { emailThreadSchema, type isPurchaseOrder } from "../types/validations";

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

async function getLatestThreadId(accessToken: string) {
  const messagesResponse = await gmail.users.messages.list(
    {
      userId: "me",
      q: "is:inbox",
      maxResults: 1,
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  const threadId = messagesResponse.data.messages?.[0]?.threadId;
  if (!threadId) {
    throw new Error("No thread found");
  }

  return threadId;
}

async function fetchAndValidateThread(threadId: string) {
  const threadData = await getThread(threadId);
  if (!threadData) {
    throw new Error("Thread not found");
  }

  const validationResult = emailThreadSchema.safeParse(threadData);
  if (!validationResult.success) {
    const errors = validationResult.error.errors
      .map((e) => e.message)
      .join(",");
    throw new Error(`Invalid thread data: ${errors}`);
  }
  return validationResult.data.messages;
}

async function getThreadData(accessToken: string) {
  try {
    const threadId = await getLatestThreadId(accessToken);
    return await fetchAndValidateThread(threadId);
  } catch (error) {
    if (isGoogleApiError(error) && error.response?.status === 401) {
      const newToken = await refreshAccessToken();
      const threadId = await getLatestThreadId(newToken);
      return await fetchAndValidateThread(threadId);
    }
    throw error;
  }
}

export const webhookHandler: RequestHandler = async (req, res) => {
  try {
    consola.info("Gmail Webhook Received");

    if (!req.body.message?.data) {
      res.status(400).send("No message data");
      return;
    }

    const accessToken = getGlobalVar("accessTokenStore");
    const emailThread = await getThreadData(accessToken);
    const extractedData = extractEmailData(emailThread);
    const {
      data: { isPurchaseOrder },
    } = await axios.post<isPurchaseOrder>(
      `${process.env.NEXT_JS_SERVER}/api/purchase-order/classify`,
      extractedData
    );
    res.status(200).json(isPurchaseOrder);
    return;
  } catch (error) {
    consola.error("Error in webhook handler:", error);
    const errorMessage =
      error instanceof Error
        ? error.message
        : "Error processing Gmail notification";
    res.status(500).send(errorMessage);
    return;
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
