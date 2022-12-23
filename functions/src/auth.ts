import * as bcrypt from "bcrypt";
import * as functions from "firebase-functions";
import {nanoid} from "nanoid";
import validator from "validator";

import admin, {getBearerToken, sendEmail} from "./core";
import {
  clearExpiredResetToken,
  clearExpiredSessions,
  sessionRequired,
} from "./middleware";

import express = require("express")
import cors = require("cors")

const app = express();
app.use(cors({origin: true}));

// Create a session for the user
async function login(req: express.Request, res: express.Response) {
  const email = req.body.email || "";
  const password = req.body.password || "";

  if (!email || !password) {
    res.status(400).json({message: "Email and password are required"});
    return;
  }

  const user = await admin
      .firestore()
      .collection("users")
      .where("email", "==", email)
      .get();

  if (user.empty) {
    res.status(400).json({message: "Invalid email or password"});
    return;
  }

  const userData = user.docs[0].data();

  const correctPassword = await bcrypt
      .compare(password, userData.password)
      .then((result) => result)
      .catch(() => {
        res.status(500).json({message: "Password comparison failed"});
        return;
      });

  if (!correctPassword) {
    res.status(400).json({message: "Invalid email or password"});
    return;
  }

  let generatedSessionHash = `session-${nanoid(32)}`;
  while (
    !(
      await admin
          .firestore()
          .collection("sessions")
          .where("hash", "==", generatedSessionHash)
          .get()
    ).empty
  ) {
    generatedSessionHash = `session-${nanoid(32)}`;
  }

  await admin
      .firestore()
      .collection("sessions")
      .add({
        hash: generatedSessionHash,
        user_id: user.docs[0].id,
        expiry: Date.now() + 604800000, // 1 week
      });

  res.status(200).json({
    message: "Login successful",
    data: {
      session: generatedSessionHash,
    },
  });
  return;
}

// Register a new user
async function register(req: express.Request, res: express.Response) {
  const email = req.body.email || "";
  const password = req.body.password || "";

  if (!email || !password) {
    res.status(400).json({message: "Email and password are required"});
    return;
  }
  if (!validator.isEmail(email)) {
    res.status(400).json({message: "Invalid email"});
    return;
  }
  if (email.length > 255) {
    res
        .status(400)
        .json({message: "Email must not be longer than 255 characters"});
    return;
  }
  if (password.length < 8) {
    res.status(400).json({message: "Password must be at least 8 character"});
    return;
  }

  const user = await admin
      .firestore()
      .collection("users")
      .where("email", "==", email)
      .get();

  if (user.empty) {
    const hashedPassword = await bcrypt
        .hash(password, 10)
        .then((hash) => hash)
        .catch(() => {
          res.status(500).json({message: "Password encryption failed"});
          return;
        });

    const newUserData = {
      id: nanoid(32),
      email: email,
      password: hashedPassword,
      first_name: "",
      last_name: "",
      registered_at: Date.now(),
    };

    await admin
        .firestore()
        .collection("users")
        .add(newUserData)
        .then(() => {
          res.status(201).json({
            message: "Registration successful",
          });
          return;
        })
        .catch(() => {
          res.status(500).json({message: "Error while creating the user"});
          return;
        });
  } else {
    res.status(400).json({message: "Email already registered"});
    return;
  }
}

// Delete the session
async function logout(req: express.Request, res: express.Response) {
  const sessionHash = getBearerToken(req.headers.authorization || "");

  if (!sessionHash) {
    return res.status(401).json({message: "Bearer token is required"});
  }

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
        .delete();

    return res.status(200).json({message: "Logout successful"});
  }
}

async function resetPassword(req: express.Request, res: express.Response) {
  const email = req.body.email || "";

  if (!email) {
    res.status(400).json({message: "Email is required"});
    return;
  }

  const user = await admin
      .firestore()
      .collection("users")
      .where("email", "==", email)
      .get();

  if (!user.empty) {
    let resetToken = Math.random().toString().split(".")[1].slice(0, 6);
    while (
      !(
        await admin
            .firestore()
            .collection("reset_password_tokens")
            .where("token", "==", resetToken)
            .get()
      ).empty
    ) {
      resetToken = Math.random().toString().split(".")[1].slice(0, 6);
    }

    await admin
        .firestore()
        .collection("reset_password_tokens")
        .add({
          token: resetToken,
          user_id: user.docs[0].id,
          expiry: Date.now() + 300, // 5 minutes,
        });

    // eslint-disable-next-line max-len
    const emailSubject = "iNotes Password Reset Request";
    // eslint-disable-next-line max-len
    const emailBody = `Your request to reset your password has been received. If you did not request a password reset, please ignore this email. If you did request a password reset, please use the following token to reset your password:\n\n${resetToken}\n\nThis token will expire in 5 minutes.`;
    const emailSuccess = await sendEmail(
        user.docs[0].data().email,
        emailSubject,
        emailBody
    );

    if (!emailSuccess) {
      res.status(500).json({message: "Error while sending the email"});
      return;
    }
  }

  res.status(200).json({message: "Password reset email sent"});
  return;
}

async function resetPasswordConfirm(
    req: express.Request,
    res: express.Response
) {
  const token = req.body.token || "";
  const newPassword = req.body.new_password || "";

  if (!token || !newPassword) {
    res.status(400).json({message: "Token and password are required"});
    return;
  }
  if (newPassword.length < 8) {
    res.status(400).json({message: "Password must be at least 8 character"});
    return;
  }

  const resetPasswordToken = await admin
      .firestore()
      .collection("reset_password_tokens")
      .where("token", "==", token)
      .get();

  if (resetPasswordToken.empty) {
    res.status(400).json({message: "Invalid token"});
    return;
  }

  const hashedPassword = await bcrypt
      .hash(newPassword, 10)
      .then((hash) => hash)
      .catch(() => {
        res.status(500).json({message: "Password encryption failed"});
        return;
      });

  await admin
      .firestore()
      .collection("users")
      .doc(resetPasswordToken.docs[0].data().user_id)
      .update({password: hashedPassword});

  await resetPasswordToken.docs[0].ref.delete();

  res.status(200).json({message: "Password reset successful"});
  return;
}

app.use(clearExpiredSessions);
app.post("/login", login);
app.post("/register", register);
app.post("/logout", sessionRequired, logout);
app.post("/reset-password", clearExpiredResetToken, resetPassword);
app.post(
    "/reset-password/confirm",
    clearExpiredResetToken,
    resetPasswordConfirm
);

export default functions.region("asia-southeast2").https.onRequest(app);
