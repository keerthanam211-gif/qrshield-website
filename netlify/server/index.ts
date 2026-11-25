// Netlify Server entry — the backend lives in /backend, the database layer in /db, the UI in /frontend.
import type { Config } from "@netlify/server";
import { app } from "../../backend/src/app.ts";

export default app;

export const config: Config = {
  path: "/api/*",
};
