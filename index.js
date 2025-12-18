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

 

    //COMPLETE ALL-ISSUES
    app.get(
      "/all-issues/admin",
      verifyIdToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const status = req.query.status;
          console.log(status);

          const query = {};
          if (status) {
            query.status = status;
          }
          const result = await issuesColl
            .find(query)
            .sort({ isBoosted: -1 })
            .toArray();
          res.status(200).json({
            success: true,
            data: result,
            message: "All Issues getting successfully !",
          });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error" });
        }
      }
    );
    // COMPLETE ALL-ISSUES-HOME
    app.get("/all-issues", verifyIdToken, async (req, res) => {
      try {
        const {
          status,
          category,
          priority,
          search,
          page = 1,
          limit = 9,
        } = req.query;
        const query = {};
        if (status) {
          query.status = status;
        }
        if (category) {
          query.category = category;
        }
        if (priority) {
          query.priority = priority;
        }

        if (search) {
          query.$or = [
            { title: { $regex: search, $options: "i" } },
            { category: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
          ];
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const issues = await issuesColl
          .find(query)
          .sort({ isBoosted: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        const totalIssues = await issuesColl.countDocuments(query);

        res.status(200).json({
          success: true,
          data: issues,
          pagination: {
            currentPage: parseInt(page),
            totalPages: Math.ceil(totalIssues / parseInt(limit)),
            totalIssues,
            hasNext: parseInt(page) < Math.ceil(totalIssues / parseInt(limit)),
            hasPrev: parseInt(page) > 1,
          },
          message: "All Issues getting successfully !",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    // COMPLETE ALL-ISSUES-HOME
    app.get("/latest-resolved-issues", async (req, res) => {
      try {
        const issues = await issuesColl
          .find({ status: { $in: ["Resolved"] } })
          .sort({ resolvedAt: -1 })
          .limit(6)
          .toArray();

        res.json({ success: true, data: issues });
      } catch (error) {
        res.status(500).json({ success: false, message: error.message });
      }
    });

    app.post("/login-user", async (req, res) => {
      try {
        const { email, password } = req.body;
        const isExists = await usersColl.findOne({ email });

        if (!isExists) {
          return res.status(401).json({
            success: false,
            message: "Invalid email !",
          });
        }

        const hashedPassword = isExists.password;
        let comparePassword = await bcrypt.compare(
          password || "Password123",
          hashedPassword
        );

        if (!comparePassword) {
          return res
            .status(401)
            .json({ success: false, message: "Invalid password !" });
        }

        res.status(200).json({
          success: true,
          message: "Login successful !",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    app.post("/create-user", async (req, res) => {
      try {
        const { name, email, picture, password } = req.body;
        let hashedPassword;
        const isExists = await usersColl.findOne({ email });

        if (isExists) {
          return res.json({
            success: false,
            message: "Already have an account email !",
          });
        }

        if (password) {
          hashedPassword = await bcrypt.hash(password, 10);
        } else {
          hashedPassword = await bcrypt.hash(password || "Password123", 10);
        }

        const firebaseUser = await admin.auth().createUser({
          email,
          password,
          displayName: name,
          photoURL: picture || "https://i.pravatar.cc/1080",
        });
        console.log("firebaseUser", { firebaseUser });

        const user_info = {
          picture: picture || "https://i.pravatar.cc/1080",
          name,
          email,
          role: "Citizen",
          createdAt: createdAt(),
          isPremium: false,
          isBlocked: false,
          uid: firebaseUser.uid,
          provider: firebaseUser.providerData[0].providerId,
        };

        user_info.password = hashedPassword;
        const user = await usersColl.insertOne(user_info);

        res.status(201).json({
          success: true,
          message: "Registration Successful !",
          data: user,
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ALL-ISSUES
    app.get("/all-staff", verifyIdToken, verifyAdmin, async (req, res) => {
      const { role, status } = req.query;
      try {
        const query = {
          role,
        };

        if (status) {
          query.status = status;
        }

        const result = await usersColl.find(query).toArray();

        res.status(200).json({
          success: true,
          data: result,
          message: "Successfully getting result from staff Collection",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
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
