const bcrypt = require("bcrypt");
const Users = require("../models/user.js");

// Authentication middleware
const isAuthMiddleware = (req, res, next) => {
    if (req.session.isAuth) {
        next();
    } else {
        res.render("login", { mess: "Not Authorized" });
    }
};

// GET = login page
const getLogin = (req, res, next) => {
    res.render("login", { mess: "" });
};

// POST = login
const postLogin = async (req, res, next) => {
    const { email, password } = req.body;

    const validUser = await Users.find({ email: email });

    if (validUser.length < 1) {
        return res.render("login", {
            mess: "Email not found. Please register",
        });
    }
    const matched = await bcrypt.compare(password, validUser[0].password);
    if (matched) {
        req.session.isAuth = true;
        res.redirect("/dashboard");
    } else {
        res.render("login", { mess: "Password not matched" });
    }
};

// GET = register page
const getRegister = (req, res, next) => {
    res.render("register", { mess: "" });
};

// POST = register
const postRegister = async (req, res, next) => {
    const { name, email, password, cpass } = req.body;
    if (
        name.length < 1 ||
        email.length < 1 ||
        password.length < 1 ||
        password != cpass
    ) {
        return res.render("register", {
            mess: "Invalid Name or Password did not match",
        });
    }
    const alreadyUser = await Users.find({ email: email });
    if (alreadyUser.length > 0) {
        return res.render("login", { mess: "Already registered user, login" });
    }
    const hashPass = await bcrypt.hash(password, 12);
    const newUser = new Users({
        name: name,
        email: email,
        password: hashPass,
    });
    newUser
        .save()
        .then(() => {
            res.render("login", { mess: "Registered successfully, login" });
        })
        .catch((err) => console.log(err));
};

// GET = dashboard page
const getDashboard = (req, res, next) => {
    res.render("dashboard");
};

// POST = logout
const postLogout = (req, res) => {
    req.session.destroy((err) => console.log(err));
    res.redirect("/");
};

// exports
module.exports = {
    getLogin,
    getRegister,
    postLogin,
    postRegister,
    getDashboard,
    isAuthMiddleware,
    postLogout,
};
