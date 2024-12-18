// Constants
export const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
export const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
export const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
export const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL!;
export const SESSION_SECRET = process.env.SESSION_SECRET || "keyboard cat";
export const GMAIL_TOPIC_NAME =
  process.env.GMAIL_TOPIC_NAME ||
  "projects/YOUR_PROJECT_ID/topics/YOUR_TOPIC_NAME";
