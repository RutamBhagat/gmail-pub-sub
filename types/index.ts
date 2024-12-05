export interface User {
  id?: string;
  displayName?: string;
  emails?: { value: string; verified?: boolean }[];
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

export const ALLOWED_EMAIL_MIME_TYPES = [
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/jpg",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "text/csv",
];
