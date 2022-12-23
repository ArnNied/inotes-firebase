import * as functions from "firebase-functions";
import {nanoid} from "nanoid";

import admin, {getBearerToken, getUserIdFromSession} from "./core";
import {clearExpiredSessions, sessionRequired} from "./middleware";

import express = require("express");
import cors = require("cors");

const app = express();
app.use(cors({origin: true}));


// Get a single note by their ID for the user
async function getNote(req: express.Request, res: express.Response) {
  const id = req.params.noteId;

  const session = getBearerToken(req.headers.authorization || "");

  const user = await admin
      .firestore()
      .collection("sessions")
      .where("hash", "==", session)
      .get();
  const userId = user.docs[0].data().user_id;

  const note = await admin
      .firestore()
      .collection("notes")
      .where("user_id", "==", userId)
      .where("id", "==", id)
      .get();

  if (note.empty) {
    res.status(404).json({message: "Note not found"});
    return;
  }

  res.status(200).json({
    message: "Note successfully retrieved",
    data: note.docs[0].data(),
  });
  return;
}


// Get all notes for the user
async function getNotes(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");

  const userId = await getUserIdFromSession(session);

  const notes = await admin
      .firestore()
      .collection("notes")
      .where("user_id", "==", userId)
      .get();

  const notesData = notes.docs.map((doc) => doc.data());

  res.status(200).json({
    message: "Notes successfully retrieved",
    data: notesData || [],
  });
  return;
}


// Create a note for the user
async function createNote(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const noteTitle = req.body.title || "";
  const noteBody = req.body.body || "";


  if (!noteTitle || !noteBody) {
    res.status(400).json({message: "Note must have a title and a body"});
    return;
  }

  let generatedNoteId = `note-${nanoid(32)}`;

  while (
    !(await admin
        .firestore()
        .collection("notes")
        .where("id", "==", generatedNoteId)
        .get())
        .empty
  ) {
    generatedNoteId = `note-${nanoid(32)}`;
  }

  const newNote = {
    id: generatedNoteId,
    user_id: userId,
    title: noteTitle,
    body: noteBody,
    created_at: Date.now(),
    last_updated: Date.now(),
  };

  await admin
      .firestore()
      .collection("notes")
      .add(newNote)
      .then(() => {
        res.status(201).json({
          message: "Note successfully created",
          data: newNote,
        });
      })
      .catch(() => {
        res.status(500).json({message: "Error while creating the note"});
      });
  return;
}


// Update existing note by their id
async function updateNote(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const noteId = req.params.noteId;
  const noteTitle = req.body.title || "";
  const noteBody = req.body.body || "";


  if (!noteTitle || !noteBody) {
    res.status(400).json({message: "Note must have a title and a body"});
    return;
  }

  const note = await admin
      .firestore()
      .collection("notes")
      .where("user_id", "==", userId)
      .where("id", "==", noteId)
      .get();

  if (note.empty) {
    res.status(404).json({message: "Note not found"});
    return;
  }

  const updatedNote = {
    title: noteTitle,
    body: noteBody,
    last_updated: Date.now(),
  };

  await admin
      .firestore()
      .collection("notes")
      .doc(note.docs[0].id)
      .update(updatedNote)
      .then(() => {
        res.status(200).json({
          message: "Note successfully modified",
          data: updatedNote,
        });
      })
      .catch(() => {
        res.status(500).json({message: "Error while updating the note"});
      });
  return;
}


// Delete existing note by their id
async function deleteNote(req: express.Request, res: express.Response) {
  const session = getBearerToken(req.headers.authorization || "");
  const userId = await getUserIdFromSession(session);

  const noteId = req.params.noteId;

  const note = await admin
      .firestore()
      .collection("notes")
      .where("user_id", "==", userId)
      .where("id", "==", noteId)
      .get();

  if (note.empty) {
    res.status(404).json({message: "Note not found"});
    return;
  }

  await admin
      .firestore()
      .collection("notes")
      .doc(note.docs[0].id)
      .delete()
      .then(() => {
        res.status(200).json({message: "Note successfully deleted"});
      })
      .catch(() => {
        res.status(500).json({message: "Error while deleting the note"});
      });
  return;
}

app.use(sessionRequired, clearExpiredSessions);
app.get("", getNotes);
app.get("/:noteId", getNote);
app.post("", createNote);
app.patch("/:noteId", updateNote);
app.delete("/:noteId", deleteNote);

export default functions.region("asia-southeast2").https.onRequest(app);
