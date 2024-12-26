import express, { Request, Response } from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
const PORT = 8080;

// Enhanced database structure with version history
interface DataVersion {
  data: string;
  signature: string;
  timestamp: number;
  publicKey: string;  // Store which key signed this version
}

// In-memory database with version history
const database: {
  currentData: DataVersion;
  history: DataVersion[];
  clientKeys: { [key: string]: string }; // Store multiple client public keys
} = {
  currentData: {
    data: "Initial Data",
    signature: "",
    timestamp: Date.now(),
    publicKey: ""
  },
  history: [],
  clientKeys: {}
};

// Middleware
app.use(cors());
app.use(express.json());

// Register client's public key
app.post("/register-key", (req: Request, res: Response) => {
  const { publicKey, clientId } = req.body;
  database.clientKeys[clientId] = publicKey;
  res.json({ message: "Public key registered" });
});

// Verify signature using stored client public key
const verifySignature = (data: string, signature: string, clientId: string): boolean => {
  try {
    const publicKey = database.clientKeys[clientId];
    if (!publicKey) return false;

    const verifier = crypto.createVerify("SHA256");
    verifier.update(data);
    return verifier.verify(publicKey, Buffer.from(signature, "base64"));
  } catch (error) {
    console.error("Verification error:", error);
    return false;
  }
};

// Enhanced POST route to update data
app.post("/", (req: Request, res: Response) => {
  const { data, signature, clientId, timestamp } = req.body;

  // Verify incoming signature
  if (!verifySignature(data, signature, clientId)) {
    return res.status(400).json({ 
      error: "Invalid signature. Data might be tampered.",
      // Return last valid version for recovery
      lastValidVersion: database.currentData
    });
  }

  // Create new version
  const newVersion: DataVersion = {
    data,
    signature,
    timestamp: timestamp || Date.now(),
    publicKey: database.clientKeys[clientId]
  };

  // Update database
  database.history.push(database.currentData);
  database.currentData = newVersion;

  res.json({ 
    message: "Data updated successfully",
    version: newVersion
  });
});

// Get version history
app.get("/history", (req: Request, res: Response) => {
  const { clientId } = req.query;
  if (!clientId || !database.clientKeys[clientId as string]) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({
    current: database.currentData,
    history: database.history
  });
});

// Verify specific version
app.post("/verify-version", (req: Request, res: Response) => {
  const { data, signature, clientId } = req.body;
  
  const isValid = verifySignature(data, signature, clientId);
  res.json({ isValid });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});