const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bcrypt = require("bcrypt");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const serviceAccount = require("./serviceAccountKey.json");
// const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
//   "utf8"
// );
// const serviceAccount = JSON.parse(decoded);

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}
const crypto = require("crypto");

const uri = process.env.DATABASE_URI;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Created At
const createdAt = () => {
  const A1 = new Date().toDateString();
  const A2 = new Date().toLocaleTimeString();
  return `${A1} ${A2}`;
};

const generateTrackingId = () => {
  const prefix = "FIX-TRC";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toLocaleUpperCase();
  return `${prefix}-${date}-${random}`;
};
console.log(generateTrackingId());

const verifyIdToken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

async function run() {
  try {
    app.use((req, res, next) => {
      console.log(
        `⚡ ${req.method} - from ${req.hostname} - to ${
          req.path
        } at ⌛ ${new Date().toLocaleString()}`
      );
      next();
    });

    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const DB = client.db("FIX_CITY");
    const usersColl = DB.collection("users");
    const issuesColl = DB.collection("issues");
    const paymentsColl = DB.collection("payments");
    const trackingsColl = DB.collection("trackings");

    const logsTrackings = async (trackingId, status, message, by) => {
      try {
        const log = {
          trackingId,
          status,
          message,
          by,
          createdAt: createdAt(),
        };
        const result = await trackingsColl.insertOne(log);
        return result;
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    };

    // const verifyRole = (requiredRole) => async (req, res, next) => {
    //   const userDoc = await usersColl.findOne({ email: req.user.email });
    //   if (!userDoc || userDoc.role !== requiredRole) {
    //     return res.status(403).json({ success: false, message: "Forbidden" });
    //   }
    //   req.userRole = userDoc.role;
    //   next();
    // };

    // Admin Middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.user.email;
      const query = { email };
      const userDoc = await usersColl.findOne(query);
      if (!userDoc || userDoc.role !== "Admin") {
        return res.status(403).json({ success: false, message: "Forbidden" });
      }
      req.userRole = userDoc.role;
      next();
    };

    // Staff middleware
    const verifyStaff = async (req, res, next) => {
      const email = req.user.email;
      const query = { email };
      const userDoc = await usersColl.findOne(query);
      if (!userDoc || userDoc?.role !== "Staff")
        return res.status(403).json({ success: false, message: "Forbidden" });
      req.userRole = userDoc.role;
      next();
    };

    // Routes
    app.get("/", (req, res) => {
      res.send("Fix City Server Running!");
    });



    app.use((req, res, next) => {
      res.status(404).json({ success: false, message: "Api not found" });
      next();
    });

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });

    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB connected successfully!");
  } catch (err) {
    console.error("Server error:", err);
  }
}
run();
