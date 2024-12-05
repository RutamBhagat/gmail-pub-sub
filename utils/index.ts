import {
  GMAIL_TOPIC_NAME,
  GOOGLE_CALLBACK_URL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
} from "../consts";
import {
  ALLOWED_EMAIL_MIME_TYPES,
  type GmailNotificationData,
  type GoogleApiError,
} from "../types";
import { getGlobalVar, setGlobalVar } from "./file-utils";

import consola from "consola";
import { google } from "googleapis";

export const gmail = google.gmail("v1");

// Utility Functions
/**
 * Decodes and parses Gmail push notification payload from base64
 * @param encodedString - Base64 encoded notification data
 */
export function decodeBase64ToJson(
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
export const refreshAccessToken = async (): Promise<string> => {
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

export const isGoogleApiError = (error: unknown): error is GoogleApiError => {
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
export const watchInbox = async () => {
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
export const getThread = async (threadId: string): Promise<object | null> => {
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

export function extractEmailData(emailThread: any[]): string {
  let extractedData = "";

  for (const email of emailThread) {
    extractedData += `Email Subject: ${
      email.payload.headers.find((h: { name: string }) => h.name === "Subject")
        ?.value || "N/A"
    }\n`;
    extractedData += `From: ${
      email.payload.headers.find((h: { name: string }) => h.name === "From")
        ?.value || "N/A"
    }\n`;
    extractedData += `To: ${
      email.payload.headers.find((h: { name: string }) => h.name === "To")
        ?.value || "N/A"
    }\n`;
    extractedData += `Date: ${
      email.payload.headers.find((h: { name: string }) => h.name === "Date")
        ?.value || "N/A"
    }\n`;
    extractedData += `Snippet:\n${email.snippet}\n`;

    const attachments: string[] = [];
    const processAttachments = (part: any) => {
      if (ALLOWED_EMAIL_MIME_TYPES.includes(part.mimeType)) {
        attachments.push(`- ${part.filename} (${part.mimeType})\n`);
      }
      if (part.parts) {
        part.parts.forEach(processAttachments);
      }
    };

    if (email.payload.parts) {
      email.payload.parts.forEach(processAttachments);
    }

    if (attachments.length > 0) {
      extractedData += `Attachments:\n${attachments.join("")}`;
    }
    extractedData += "\n";
    extractedData += `----------------------------------------\n`; // Separator between emails
  }

  return extractedData;
}
