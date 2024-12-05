export interface User {
  id?: string;
  displayName?: string;
  emails?: { value: string; verified?: boolean }[];
}

export interface GmailNotificationData {
  emailAddress: string;
  historyId: string;
}

export interface GoogleProfile extends User {
  accessToken?: string;
  refreshToken?: string;
}

export interface GoogleApiError {
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
