import * as fs from "fs";
import * as path from "path";

const VARS_FILE = path.join(__dirname, "global-vars.json");

// Initialize file if it doesn't exist
if (!fs.existsSync(VARS_FILE)) {
  const initialData = {
    accessTokenStore: "",
    refreshTokenStore: "",
    historyId: "",
    emailAddress: "",
    threadId: "",
    messageDetails: {},
  };
  fs.writeFileSync(VARS_FILE, JSON.stringify(initialData, null, 4));
}

export function getGlobalVar(key: string) {
  const data = JSON.parse(fs.readFileSync(VARS_FILE, "utf8"));
  return data[key];
}

export function setGlobalVar(key: string, value: any) {
  const data = JSON.parse(fs.readFileSync(VARS_FILE, "utf8"));
  data[key] = value;
  fs.writeFileSync(VARS_FILE, JSON.stringify(data, null, 4));
}
