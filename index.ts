import express, { Router } from "express";
import cors from "cors";
import SgidClient, { generatePkcePair } from "@opengovsg/sgid-client";
import * as dotenv from "dotenv";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import open from "open";

dotenv.config();

const PORT = 5001;
const redirectUri = String(
  process.env.SGID_REDIRECT_URI ?? `https://vccm-sgid.onrender.com/api/redirect`
);
const frontendHost = String(
  process.env.SGID_FRONTEND_HOST ?? "https://cors-anywhere.herokuapp.com/"
);

const sgid = new SgidClient({
  clientId: String(process.env.SGID_CLIENT_ID),
  clientSecret: String(process.env.SGID_CLIENT_SECRET),
  privateKey: String(process.env.SGID_PRIVATE_KEY),
  redirectUri,
});

const app = express();

const apiRouter = Router();

const SESSION_COOKIE_NAME = "exampleAppSession";
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
};

type SessionData = Record<
  string,
  | {
      nonce?: string;
      accessToken?: string;
      codeVerifier?: string;
      sub?: string;
    }
  | undefined
>;

/**
 * In-memory store for session data.
 * In a real application, this would be a database.
 */
const sessionData: SessionData = {};

app.use(
  cors({
    credentials: true,
    origin: frontendHost,
  })
);

app.get("/", (req, res) => {
  res.send("Welcome");
});

apiRouter.get("/auth-url", (req, res) => {
  const sessionId = crypto.randomUUID();

  // Generate a PKCE pair
  const { codeChallenge, codeVerifier } = generatePkcePair();

  const { url, nonce } = sgid.authorizationUrl({
    codeChallenge,
    scope: ["openid", "myinfo.name"],
  });
  sessionData[sessionId] = {
    // state,
    nonce,
    codeVerifier,
  };
  return res
    .cookie(SESSION_COOKIE_NAME, sessionId, SESSION_COOKIE_OPTIONS)
    //   {
    //   httpOnly: true,
    //   sameSite: "none",
    // })
    .json({ url });
});

apiRouter.get("/redirect", async (req, res): Promise<void> => {
  const authCode = String(req.query.code);
  const state = String(req.query.state);
  const sessionId = String(req.cookies[SESSION_COOKIE_NAME]);

  const session = { ...sessionData[sessionId] };

  // Validate that the code verifier exists for this session
  if (session?.codeVerifier === undefined) {
    res.redirect(`${frontendHost}/error`);
    return;
  }

  // Exchange the authorization code and code verifier for the access token
  const { codeVerifier, nonce } = session;
  const { accessToken, sub } = await sgid.callback({
    code: authCode,
    nonce,
    codeVerifier,
  });

  session.accessToken = accessToken;
  session.sub = sub;
  sessionData[sessionId] = session;

  // Successful login, redirect to logged in state
  res.redirect(`${frontendHost}/chat`);
});

apiRouter.get("/userinfo", async (req, res) => {
  const sessionId = String(req.cookies[SESSION_COOKIE_NAME]);

  // Retrieve the access token and sub
  const session = sessionData[sessionId];
  const accessToken = session?.accessToken;
  const sub = session?.sub;

  // User is not authenticated
  if (session === undefined || accessToken === undefined || sub === undefined) {
    return res.sendStatus(401);
  }
  const userinfo = await sgid.userinfo({
    accessToken,
    sub,
  });

  return res.json(userinfo);
});

apiRouter.get("/logout", async (req, res) => {
  const sessionId = String(req.cookies[SESSION_COOKIE_NAME]);
  delete sessionData[sessionId];
  return res
    .clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS)
    .sendStatus(200);
});

const initServer = async (): Promise<void> => {
  try {
    app.use(cookieParser());
    app.use("/api", apiRouter);

    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
      void open(`http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error(
      "Something went wrong while starting the server. Please restart the server."
    );
    console.error(error);
  }
};

void initServer();
