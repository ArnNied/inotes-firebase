import * as bcrypt from "bcrypt";
import * as functions from "firebase-functions";
import validator from "validator";

import admin, {getBearerToken, getUserIdFromSession} from "./core";
import {clearExpiredSessions, sessionRequired} from "./middleware";

import express = require("express")
import cors = require("cors")

const app = express();
app.use(cors({origin: true}));

// Retrive a user's information
async function getUser(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const user = await admin.firestore().collection("users").doc(userId).get();

  if (!user.exists) {
    res.status(404).json({message: "User not found"});
    return;
  }

  const userData = user.data();
  if (!userData) {
    res.status(500).json({message: "Internal server error"});
    return;
  }

  res.status(200).json({
    message: "User successfully retrieved",
    data: userData,
  });
  return;
}

// Update a user's information
async function updateUserInfo(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const email = req.body.email || "";
  const firstName = req.body.first_name || "";
  const lastName = req.body.last_name || "";

  const user = await admin.firestore().collection("users").doc(userId).get();

  if (!user.exists) {
    res.status(404).json({message: "User not found"});
    return;
  }

  const userData = user.data();
  if (!userData) {
    res.status(500).json({message: "Internal server error"});
    return;
  }

  if (!email) {
    res.status(400).json({message: "Email is required"});
    return;
  }
  if (!validator.isEmail(email)) {
    res.status(400).json({message: "Invalid email"});
    return;
  }
  if (firstName.length > 255) {
    res.status(400).json({
      message: "First name must be less than 255 characters",
    });
    return;
  }
  if (lastName.length > 255) {
    res.status(400).json({
      message: "Last name must be less than 255 characters",
    });
    return;
  }

  const userWithEmail = await admin
      .firestore()
      .collection("users")
      .where("email", "==", email)
      .get();

  if (!userWithEmail.empty && userWithEmail.docs[0].id !== userId) {
    res.status(400).json({message: "Email already in use"});
    return;
  }

  await admin.firestore().collection("users").doc(userId).update({
    email,
    first_name: firstName,
    last_name: lastName,
  });

  res.status(200).json({
    message: "User info successfully updated",
    data: {
      ...userData,
      email,
      first_name: firstName,
      last_name: lastName,
    },
  });
  return;
}

// Delete a user
async function deleteUser(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const user = await admin.firestore().collection("users").doc(userId).get();

  if (!user.exists) {
    res.status(404).json({message: "User not found"});
    return;
  }

  // Delete all sessions concerning the user
  await admin
      .firestore()
      .collection("sessions")
      .where("user_id", "==", userId)
      .get()
      .then((snapshot) => {
        snapshot.forEach((doc) => {
          doc.ref.delete();
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).json({message: "Internal server error"});
        return;
      });

  // Delete all password reset tokens concerning the user
  await admin
      .firestore()
      .collection("password_reset_tokens")
      .where("user_id", "==", userId)
      .get()
      .then((snapshot) => {
        snapshot.forEach((doc) => {
          doc.ref.delete();
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).json({message: "Internal server error"});
        return;
      });

  // Delete all notes concerning the user
  await admin
      .firestore()
      .collection("notes")
      .where("user_id", "==", userId)
      .get()
      .then((snapshot) => {
        snapshot.forEach((doc) => {
          doc.ref.delete();
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).json({message: "Internal server error"});
        return;
      });

  // Delete the user
  await admin
      .firestore()
      .collection("users")
      .doc(userId)
      .delete()
      .catch((err) => {
        console.log(err);
        res.status(500).json({message: "Internal server error"});
        return;
      });

  res.status(200).json({message: "User successfully deleted"});
  return;
}

// Change a user's password
async function changePassword(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const oldPassword = req.body.current_password || "";
  const newPassword = req.body.new_password || "";

  const user = await admin.firestore().collection("users").doc(userId).get();

  if (!user.exists) {
    res.status(404).json({message: "User not found"});
    return;
  }

  const userData = user.data();
  if (!userData) {
    res.status(500).json({message: "Internal server error"});
    return;
  }

  if (!oldPassword) {
    res.status(400).json({message: "Old password is required"});
    return;
  }
  if (!newPassword) {
    res.status(400).json({message: "New password is required"});
    return;
  }
  if (newPassword.length < 8) {
    res.status(400).json({
      message: "New password must be at least 8 characters",
    });
    return;
  }

  const passwordMatch = await bcrypt
      .compare(oldPassword, userData.password)
      .then((result) => result)
      .catch(() => {
        res.status(500).json({message: "Password comparison failed"});
        return;
      });

  if (!passwordMatch) {
    res.status(400).json({message: "Incorrect old password"});
    return;
  }

  const hashedPassword = await bcrypt
      .hash(newPassword, 10)
      .then((hash) => hash)
      .catch(() => {
        res.status(500).json({message: "Password encryption failed"});
        return;
      });

  await admin.firestore().collection("users").doc(userId).update({
    password: hashedPassword,
  });

  res.status(200).json({message: "Password successfully changed"});
  return;
}

app.use(clearExpiredSessions, sessionRequired);
app.get("", getUser);
app.patch("", updateUserInfo);
app.delete("", deleteUser);
app.post("/change-password", changePassword);

export default functions.region("asia-southeast2").https.onRequest(app);
