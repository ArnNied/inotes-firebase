import admin, {getBearerToken} from "./core";

import express = require("express")

// Check if the user is logged in
// If the user is logged in, update the session expiry
export async function sessionRequired(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
  if (!req.headers.authorization?.startsWith("Bearer ")) {
    return res.status(401).json({
      message: `Expected (Bearer <token>). Received: ${req.headers.authorization}`, // eslint-disable-line max-len
    });
  }

  const sessionHash = getBearerToken(req.headers.authorization || "");

  const session = await admin
      .firestore()
      .collection("sessions")
      .where("hash", "==", sessionHash)
      .get();

  if (session.empty) {
    return res.status(401).json({message: "Invalid session"});
  } else {
    await admin
        .firestore()
        .collection("sessions")
        .doc(session.docs[0].id)
        .update({
          expiry: Date.now() + 604800000, // 1 week
        });
    return next();
  }
}

export async function clearExpiredSessions(
    req: express.Request, // eslint-disable-line @typescript-eslint/no-unused-vars, max-len
    res: express.Response, // eslint-disable-line @typescript-eslint/no-unused-vars, max-len
    next: express.NextFunction
) {
  const sessions = await admin.firestore().collection("sessions").get();

  sessions.docs.forEach(async (session) => {
    if (session.data().expiry < Date.now()) {
      await admin.firestore().collection("sessions").doc(session.id).delete();
    }
  });

  return next();
}

export async function clearExpiredResetToken(
    req: express.Request, // eslint-disable-line @typescript-eslint/no-unused-vars, max-len
    res: express.Response, // eslint-disable-line @typescript-eslint/no-unused-vars, max-len
    next: express.NextFunction
) {
  const tokens = await admin
      .firestore()
      .collection("password_reset_tokens")
      .get();

  tokens.docs.forEach(async (token) => {
    if (token.data().expiry < Date.now()) {
      await admin
          .firestore()
          .collection("password_reset_tokens")
          .doc(token.id)
          .delete();
    }
  });

  return next();
}
