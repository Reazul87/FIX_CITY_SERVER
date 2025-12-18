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

    app.get("/citizen-dashboard", verifyIdToken, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email) {
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        }

        const query = { issueBy: email };

        const totalIssues = await issuesColl.countDocuments(query);

        const pending = await issuesColl.countDocuments({
          ...query,
          status: { $regex: /^pending$/i },
        });

        const inProgress = await issuesColl.countDocuments({
          ...query,
          status: { $regex: /^in.?progress$/i },
        });

        const resolved = await issuesColl.countDocuments({
          ...query,
          status: { $regex: /^(closed|resolved)$/i },
        });

        const totalPaymentsResult = await paymentsColl
          .aggregate([
            {
              $match: {
                customer_email: email,
                payment_status: "paid",
              },
            },
            {
              $group: {
                _id: null,
                total: { $sum: "$amount" },
              },
            },
          ])
          .toArray();

        const totalPayments =
          totalPaymentsResult.length > 0
            ? totalPaymentsResult[0].total / 100
            : 0;

        const monthlyPayments = await paymentsColl
          .aggregate([
            {
              $match: {
                customer_email: email,
                payment_status: "paid",
              },
            },
            {
              $addFields: {
                paidAtDate: { $toDate: "$paidAt" },
              },
            },
            {
              $group: {
                _id: {
                  year: { $year: "$paidAtDate" },
                  month: { $month: "$paidAtDate" },
                },
                totalAmount: { $sum: "$amount" },
                count: { $sum: 1 },
              },
            },
            {
              $project: {
                monthYear: {
                  $dateToString: {
                    format: "%B %Y",
                    date: {
                      $dateFromParts: {
                        year: "$_id.year",
                        month: "$_id.month",
                        day: 1,
                      },
                    },
                  },
                },
                totalAmount: 1,
                count: 1,
              },
            },
            { $sort: { "_id.year": -1, "_id.month": -1 } },
          ])
          .toArray();

        const issues = await issuesColl
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();

        res.status(200).json({
          success: true,
          data: {
            issues,
            stats: {
              totalIssues,
              pending,
              inProgress,
              resolved,
              totalPayments,
              monthlyPayments,
            },
          },
          message: "Dashboard data fetched successfully",
        });
      } catch (error) {
        console.error("Citizen Dashboard Error:", error);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    app.get(
      "/staff-dashboard",
      verifyIdToken,
      verifyStaff,
      async (req, res) => {
        try {
          const staff_email = req.query.staff_email;
          if (!staff_email)
            return res.status(400).json({ message: "Staff email required" });

          const query = { staff_email };

          const assignedIssues = await issuesColl
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();

          const totalAssigned = assignedIssues.length;
          const pending = assignedIssues.filter(
            (i) => i.status === "Pending"
          ).length;
          const inProgress = assignedIssues.filter(
            (i) => i.status === "In-Progress"
          ).length;
          const resolved = assignedIssues.filter((i) =>
            ["Closed", "Resolved"].includes(i.status)
          ).length;

          const today = new Date();
          today.setHours(0, 0, 0, 0);
          const tomorrow = new Date(today);
          tomorrow.setDate(tomorrow.getDate() + 1);

          const todaysIssues = assignedIssues.filter((i) => {
            const dateStr = i.assignedAt || i.reportedAt || i.createdAt;
            if (!dateStr) return false;

            const issueDate = new Date(dateStr);
            if (isNaN(issueDate.getTime())) return false;

            return issueDate >= today && issueDate < tomorrow;
          });

          const monthMap = {};
          assignedIssues
            .filter((i) => ["Closed", "Resolved"].includes(i.status))
            .forEach((i) => {
              const dateStr = i.updatedAt || i.createdAt || i.reportedAt;
              if (!dateStr) return;
              const date = new Date(dateStr);
              if (isNaN(date.getTime())) return;

              const year = date.getFullYear();
              const month = date.getMonth() + 1;
              const key = `${year}-${month}`;

              monthMap[key] = monthMap[key] || { year, month, count: 0 };
              monthMap[key].count += 1;
            });

          const monthlyResolved = Object.values(monthMap)
            .map((item) => ({
              monthYear: new Date(item.year, item.month - 1).toLocaleString(
                "en-US",
                {
                  month: "long",
                  year: "numeric",
                }
              ),
              count: item.count,
            }))
            .sort((a, b) => new Date(b.monthYear) - new Date(a.monthYear));

          res.json({
            success: true,
            data: {
              assignedIssues,
              stats: {
                totalAssigned,
                pending,
                inProgress,
                resolved,
                todaysTasks: todaysIssues.length,
                todaysIssues,
                monthlyResolved,
              },
            },
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({ success: false, message: "Server Error" });
        }
      }
    );

    app.get(
      "/admin-dashboard",
      verifyIdToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const totalIssues = await issuesColl.countDocuments();
          const pending = await issuesColl.countDocuments({
            status: "Pending",
          });
          const inProgress = await issuesColl.countDocuments({
            status: "In-Progress",
          });
          const resolved = await issuesColl.countDocuments({
            status: { $in: ["Closed", "Resolved"] },
          });
          const rejected = await issuesColl.countDocuments({
            status: "Rejected",
          });

          const paymentAgg = await paymentsColl
            .aggregate([
              { $match: { payment_status: "paid" } },
              { $group: { _id: null, total: { $sum: "$amount" } } },
            ])
            .toArray();

          const totalPayments =
            paymentAgg.length > 0 ? paymentAgg[0].total / 100 : 0;

          // Latest Data
          const latestIssues = await issuesColl
            .find()
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();

          const latestPayments = await paymentsColl
            .find({ payment_status: "paid" })
            .sort({ paidAt: -1 })
            .limit(5)
            .toArray();

          const latestUsers = await usersColl
            .find()
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();

          const allPayments = await paymentsColl
            .find({ payment_status: "paid" })
            .toArray();

          const monthMap = {};

          allPayments.forEach((payment) => {
            const dateStr = payment.paidAt;
            if (!dateStr) return;

            const date = new Date(dateStr);
            if (isNaN(date.getTime())) return;

            const year = date.getFullYear();
            const month = date.getMonth() + 1;
            const key = `${year}-${month.toString().padStart(2, "0")}`;

            monthMap[key] = monthMap[key] || { year, month, totalAmount: 0 };
            monthMap[key].totalAmount += payment.amount;
          });

          const monthlyPayments = Object.values(monthMap)
            .map((item) => ({
              monthYear: new Date(item.year, item.month - 1).toLocaleString(
                "en-US",
                {
                  month: "long",
                  year: "numeric",
                }
              ),
              totalAmount: item.totalAmount,
            }))
            .sort((a, b) => new Date(b.monthYear) - new Date(a.monthYear));

          res.json({
            success: true,
            data: {
              stats: {
                totalIssues,
                pending,
                inProgress,
                resolved,
                rejected,
                totalPayments,
              },
              latestIssues,
              latestPayments,
              latestUsers,
              monthlyPayments,
            },
          });
        } catch (error) {
          console.error("Admin Dashboard Error:", error);
          res.status(500).json({ success: false, message: "Server Error" });
        }
      }
    );

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

    //COMPLETE ISSUES-DETAILS
    app.get("/issue-trackings/:trackingId", verifyIdToken, async (req, res) => {
      try {
        const trackingId = req.params.trackingId;
        const query = { trackingId };
        const result = await trackingsColl
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res
          .status(200)
          .json({ success: true, data: result, message: "Issue Trackings" });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ALL-ISSUES-ADMIN
    app.patch(
      "/issue/:id/reject",
      verifyIdToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const query = { _id: new ObjectId(id) };
          const { rejected_id, trackingId } = req.body;

          const update_info = {
            $set: {
              status: "Rejected",
              rejected: true,
              rejected_id,
              rejectedAt: createdAt(),
            },
          };

          const result = await issuesColl.updateOne(query, update_info);

          await logsTrackings(
            trackingId,
            "Issue Rejected",
            "Issue rejected by authority.",
            req.userRole
          );
          res
            .status(200)
            .json({ success: true, data: result, message: "Issue Rejected !" });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    app.patch(
      "/issue/status/:id",
      verifyIdToken,
      verifyStaff,
      async (req, res) => {
        try {
          const id = req.params.id;
          const query = { _id: new ObjectId(id) };
          const { status, trackingId } = req.body;
          const at = createdAt();
          const update_info = {
            $set: { status: status },
          };
          if (status === "Resolved") {
            update_info.$set = { status: status, resolvedAt: at };
          }
          console.log(status);

          const result = await issuesColl.updateOne(query, update_info);

          await logsTrackings(
            trackingId,
            `Issue ${status}`,
            "Staff is working on issue",
            req.userRole
          );
          res.status(200).json({
            success: true,
            data: result,
            message: `Issue ${status} Successful !`,
          });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    //COMPLETE ALL-ISSUES-ADMIN
    app.get("/user/:id", verifyIdToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const status = req.params.status;
        const query = { _id: new ObjectId(id) };
        if (status) {
          query.status = status;
        }

        const result = await usersColl.findOne(query);

        res.status(200).json({
          success: true,
          data: result,
          message: "Assigning Staff by id Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ASSIGNED-ISSUES
    app.get(
      "/issue/:staff_id/assigned",
      verifyIdToken,
      verifyStaff,
      async (req, res) => {
        try {
          const staff_Id = req.params.staff_id;
          const { status, priority } = req.query;
          const query = { staff_Id: staff_Id };

          if (status) {
            query.status = status;
          }
          if (priority) {
            query.priority = priority;
          }

          const result = await issuesColl.find(query).toArray();
          res
            .status(200)
            .json({ success: true, data: result, message: "Assigned Issue" });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    //COMPLETE ALL-ISSUES-ADMIN
    app.patch(
      "/assigning-staff/:id",
      verifyIdToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const query = {
            _id: new ObjectId(id),
          };
          const {
            staff_Id,
            staff_picture,
            staff_name,
            staff_email,
            trackingId,
          } = req.body;

          const assigned = createdAt();

          const update_info = {
            staff_Id,
            staff_picture,
            staff_name,
            staff_email,
            assignedAt: assigned,
          };

          const update = {
            $set: { ...update_info, assigned: true },
          };

          const issue = await issuesColl.updateOne(query, update);

          await logsTrackings(
            trackingId,
            "Assigned Staff",
            `Staff has been assigned to this issue`,
            req.userRole
          );
          res.status(200).json({
            success: true,
            data: issue,
            message: "Assign Staff Successful !",
          });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    //COMPLETE MANAGE-USERS
    app.get("/all-users", verifyIdToken, verifyAdmin, async (req, res) => {
      try {
        const { role } = req.query;

        const query = {
          role: role,
        };

        const result = await usersColl
          .find(query)
          .sort({ isPremium: -1 })
          .toArray();

        res.status(200).json({
          success: true,
          data: result,
          message: "Successfully getting result from users Collection",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE MANAGE-USERS
    app.patch(
      "/block-unblock",
      verifyIdToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { isBlocked, id } = req.body;
          const query = { _id: new ObjectId(id) };

          const update_info = {
            $set: { isBlocked: isBlocked },
          };

          const result = await usersColl.updateOne(query, update_info);
          res.send({
            success: true,
            data: result,
            message: "User status updated",
          });
        } catch (error) {
          console.log(error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    //COMPLETE MANAGE-STAFF
    app.post("/create-staff", verifyIdToken, verifyAdmin, async (req, res) => {
      try {
        const { name, email, picture, phone, password } = req.body;
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
          phone,
          role: "Staff",
          createdAt: createdAt(),
          isPremium: false,
          isBlocked: false,
          uid: firebaseUser.uid,
          provider: "password",
          status: "Available",
        };

        user_info.password = hashedPassword;
        const user = await usersColl.insertOne(user_info);

        res.status(201).json({
          success: true,
          message: "Staff Registration Successful !",
          data: user,
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE MANAGE-STAFF
    app.delete("/staff/:id", verifyIdToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const query = { _id: new ObjectId(id) };
        const result = await usersColl.deleteOne(query);
        res.send({
          success: true,
          data: result,
          message: "Issues Deleted Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ISSUES-DETAILS
    app.get("/issue/:id", verifyIdToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await issuesColl.findOne(query);

        res.status(200).json({
          success: true,
          data: result,
          message: "Issues by id Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ISSUES-DETAILS
    app.get("/payment/:transactionId", verifyIdToken, async (req, res) => {
      try {
        const transactionId = req.params.transactionId;
        const query = { transactionId: transactionId };
        const result = await paymentsColl.findOne(query);

        res.status(200).json({
          success: true,
          data: result,
          message: "Payment by id Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE PAYMENTS
    app.get("/payments-admin", verifyIdToken, verifyAdmin, async (req, res) => {
      try {
        const { type } = req.query;
        const query = {};
        if (type) {
          query.plan = type;
        }
        const result = await paymentsColl.find(query).toArray();

        res.status(200).json({
          success: true,
          data: result,
          message: "Payments history Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    app.post("/create-issue", verifyIdToken, async (req, res) => {
      const { title, category, description, location, image, issueBy, userId } =
        req.body;
      try {
        const trackingId = generateTrackingId();
        const issue_info = {
          image,
          title,
          category,
          location,
          description,
          issueBy,
          reportedAt: createdAt(),
          status: "Pending",
          priority: "Low",
          userId,
          upvote: 0,
          upvotedBy: [],
          trackingId: trackingId,
        };
        const report = await issuesColl.insertOne(issue_info);

        await logsTrackings(
          trackingId,
          "Issue Reported",
          "Issue has been reported to develop country",
          req.userRole
        );

        res.status(201).json({
          success: true,
          message: "Reported Successful !",
          data: report,
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    app.get("/see-issues/:email", verifyIdToken, async (req, res) => {
      try {
        const email = req.params.email;
        const { status, category, priority } = req.query;

        const query = { issueBy: email };
        console.log(email, query);

        if (status) {
          query.status = status;
        }

        if (category) {
          query.category = category;
        }

        if (priority) {
          query.priority = priority;
        }

        const issues = await issuesColl.find(query).toArray();
        res.status(200).json({
          success: true,
          data: issues,
          message: "Successfully Reported Issues getting",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ISSUES-DETAILS
    app.patch("/update-issue/:id", verifyIdToken, async (req, res) => {
      try {
        const id = req.params.id;
        const update = req.body;

        const query = { _id: new ObjectId(id) };
        const update_info = {
          $set: { ...update },
        };
        const result = await issuesColl.updateOne(query, update_info);

        await logsTrackings(
          update.trackingId,
          "Issue Updated",
          "Updated issue details for better clarity.",
          req.userRole
        );

        res.status(200).json({
          success: true,
          data: result,
          message: "Updated Issue Successful !",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE PROFILE
    app.patch("/status/:id/staff", verifyIdToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const update = req.body;
        const update_info = {
          $set: update,
        };

        const result = await usersColl.updateOne(query, update_info);
        res.status(200).json({
          success: true,
          data: result,
          message: `Staff goes to ${update.status}`,
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ISSUES-DETAILS
    app.get("/see-user/:email/role", verifyIdToken, async (req, res) => {
      try {
        const email = req.params.email;
        const result = await usersColl.findOne({ email });
        res
          .status(200)
          .json({ success: true, result, message: "Getting role" });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE PROFILE
    app.get("/see-user/:email", verifyIdToken, async (req, res) => {
      try {
        const { email } = req.params;
        const { role } = req.query;
        const query = {
          email,
        };

        if (role) {
          query.role = role;

          const result = await usersColl.findOne(query);
          return res.status(200).json({
            success: true,
            result,
            message: "Successfully getting result from users Collection",
          });
        }

        const result = await usersColl.findOne(query);
        res.status(200).json({
          success: true,
          result,
          message: "Successfully getting result from users Collection",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE PROFILE
    app.patch(
      "/update-user/:email/profile",
      verifyIdToken,
      async (req, res) => {
        try {
          const { picture, name } = req.body;
          const emailToUpdate = req.params.email;

          const requesterEmail = req.user.email;

          if (requesterEmail !== emailToUpdate) {
            return res.status(403).json({
              success: false,
              message: "Forbidden: You can only update your own profile.",
            });
          }
          const query = { email: emailToUpdate };

          const update = {
            $set: {
              picture: picture,
              name,
            },
          };

          const result = await usersColl.updateOne(query, update);

          if (result.matchedCount === 0) {
            return res
              .status(404)
              .json({ success: false, message: "User not found." });
          }

          res.status(200).json({
            success: true,
            result,
            message: "Update profile successful",
          });
        } catch (error) {
          console.error("Profile update error:", error.message);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error !" });
        }
      }
    );

    //COMPLETE ALL-ISSUES-HOME
    app.patch("/issues/:issueId/upvote", verifyIdToken, async (req, res) => {
      try {
        const id = req.params.issueId;
        const { upvotedBy } = req.body;
        const query = {
          _id: new ObjectId(id),
          upvotedBy: { $ne: upvotedBy },
        };

        const isExist = await issuesColl.findOne({ upvotedBy });

        if (isExist) {
          return res.status(400).json({
            success: false,
            message: "You already upvoted this issue",
          });
        }

        const update_info = {
          $addToSet: { upvotedBy },
          $inc: {
            upvote: 1,
          },
        };

        const result = await issuesColl.updateOne(query, update_info);

        console.log(isExist, update_info);
        res
          .status(200)
          .json({ success: true, data: result, message: "Issue upvoted !" });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //COMPLETE ISSUES-DETAILS
    app.delete("/delete-issue", verifyIdToken, async (req, res) => {
      try {
        const { id, trackingId } = req.query;
        const query = { _id: new ObjectId(id) };
        const result = await issuesColl.deleteOne(query);

        await logsTrackings(
          trackingId,
          "Issue Deleted",
          "Issue removed from system.",
          req.userRole
        );

        res.send({
          success: true,
          data: result,
          message: "Issues Deleted Successful",
        });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error !" });
      }
    });

    //ISSUE-BOOST-PAYMENT
    app.post("/boost-issue-payment-checkout-session", async (req, res) => {
      try {
        const issue_info = req.body;

        const amount = parseInt(issue_info.cost) * 100;
        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "bdt",
                product_data: {
                  name: issue_info.issue_name,
                },
                unit_amount: amount,
              },
              quantity: 1,
            },
          ],
          customer_email: issue_info.issueBy,
          mode: "payment",
          metadata: {
            issue_id: issue_info.issue_id,
            issue_name: issue_info.issue_name,
            trackingId: issue_info.trackingId,
          },
          success_url: `${process.env.SITE_DOMAIN}/payment-success/?success=true&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/payment-cancelled/${issue_info.issue_id}`,
        });

        res.send({ url: session.url });
      } catch (error) {
        console.log(error.message);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    app.patch("/payment-boost-success", async (req, res) => {
      const session_id = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(session_id);
      const paid = createdAt();

      const trackingId = session.metadata.trackingId;
      const transactionId = session.payment_intent;
      const query = { transactionId: transactionId };
      const isExists = await paymentsColl.findOne(query);
      if (isExists) {
        return res.send({
          success: true,
          data: isExists,
          message: "Already Paid!",
        });
      }

      if (session.payment_status === "paid") {
        const payForId = session.metadata.issue_id;
        const query = { _id: new ObjectId(payForId) };
        const update = {
          $set: {
            paidAt: paid,
            isBoosted: true,
            priority: "High",
            transactionId: session.payment_intent,
          },
        };

        const result = await issuesColl.updateOne(query, update);

        const payment_success = {
          plan: "Issue Boost",
          amount: session.amount_total / 100,
          currency: session.currency,
          payment_status: session.payment_status,
          customer_email: session.customer_email,
          issue_id: session.metadata.issue_id,
          issue_name: session.metadata.issue_name,
          transactionId: session.payment_intent,
          paidAt: paid,
          trackingId,
        };
        console.log(payment_success.trackingId);

        const result2 = await paymentsColl.insertOne(payment_success);

        await logsTrackings(
          trackingId,
          "Issue Boosted Successful",
          "Priority increased to high.",
          "Citizen"
        );
        return res.send({
          success: true,
          data: payment_success,
          message: "Issue Boost Successful!",
          transactionId: payment_success.transactionId,
        });
      }

      res.send({ success: false });
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
