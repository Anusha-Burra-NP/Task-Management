const express = require("express");
const { protect, adminOnly } = require("../middlewares/authMiddleware");
const { getUsers, getUserById, deleteUser } = require("../controllers/userController");

const router = express.Router();

//user Management Routes
router.get("/", protect, adminOnly, getUsers); //Get all users Admin only
router.get("/:id", protect, getUserById); //Get a specific user
// router.delete("/:id", protect, adminOnly, deleteUser) //Delete user (Admin Only)

module.exports = router