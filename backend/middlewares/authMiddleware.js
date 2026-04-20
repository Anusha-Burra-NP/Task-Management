const jwt = require("jsonwebtoken");
const user = require("../models/User");

//Middleware to protect users
const protect = async (req, res, next) => {
    try {
        let token = req.headers.authorization;

        if (token && token.startsWith("Bearer")) {
            token = token.split(" ")[1]; //Extract token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await user.findById(decoded.id).select("-password");
            next();
        } else {
            res.status(401).json({ messgae: "Not authorized, no token "});
        }
    } catch(error) {
        res.status(401).json({ message: "Token failure", error: error.message });
    }
};

//Middleware for admin only access
const adminOnly =  (req, res, next) => {
    if (req.user && req.user.role === "admin") {
        next();
    } else {
        res.status(403).json({ message: "Access denied, admin only" });
    }
};

module.exports = { protect, adminOnly };

