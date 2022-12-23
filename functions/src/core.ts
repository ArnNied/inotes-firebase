import * as admin from "firebase-admin";

import nodemailer = require("nodemailer");


export function getBearerToken(authorization: string) {
  return authorization.split(" ")[1] || "";
}

export async function getUserIdFromSession(session: string) {
  const sessionDocument = await admin
      .firestore()
      .collection("sessions")
      .where("hash", "==", session)
      .get();

  if (sessionDocument.empty) {
    return "";
  } else {
    return sessionDocument.docs[0].data().user_id;
  }
}

export async function sendEmail(
    recipient: string,
    subject: string,
    body: string
): Promise<boolean> {
  const smtpTransport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: 465,
    secure: true, // use TLS
    auth: {
      user: process.env.NODEMAILER_EMAIL,
      pass: process.env.NODEMAILER_PASSWORD,
    },
  });
  const mailOptions = {
    to: recipient,
    subject: subject,
    text: body,
  };

  return smtpTransport
      .sendMail(mailOptions).then(() => true)
      .catch((error: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any, max-len
        console.log(error);
        return false;
      });
}

// The Firebase Admin SDK to access Firestore.
admin.initializeApp();

export default admin;
