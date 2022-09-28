const User = require("../models/user.model");
const authUtil = require('../util/authentication');
const validation = require('../util/validation');
const sessionFlash = require('../util/session-flash');

function getSignup(req, res) {
    let sessionData = sessionFlash.getSessionData(req);

    if (!sessionData) {
        sessionData = {
            email: '',
            confirmEmail: '',
            password: '',
            fullname: '',
            phonenumber: '',
            street: '',
            postal: '',
            city: '',
        };
    }

    res.render("customer/auth/signup", { inputData: sessionData });
}

async function signup(req, res, next) {
    const enteredData = {
        email: req.body.email, 
        confirmEmail: req.body['confirm-email'],
        password: req.body.password, 
        fullname: req.body.fullname, 
        phonenumber: req.body.phonenumber,
        street: req.body.street, 
        postal: req.body.postal, 
        city: req.body.city,
    };

    if (
        !validation.userDetailsAreValid(
            req.body.email, 
            req.body.password, 
            req.body.fullname, 
            req.body.phonenumber,
            req.body.street, 
            req.body.postal, 
            req.body.city
        ) || 
        !validation.emailIsConfirmed(req.body.email, req.body['confirm-email'])
    ) {
        sessionFlash.flashDataToSession(
            req, 
            {
                errorMessage: 
                    'Please check your input, Password must be at least 6 character long, postal code must be 5 character long.',
                ...enteredData
            }, 
            function() {
                res.redirect('/signup')
            }
        );
        return;
    }

    const user = new User(
        req.body.email, 
        req.body.password, 
        req.body.fullname,
        req.body.phonenumber,
        req.body.street, 
        req.body.postal, 
        req.body.city,
    );

    try {
        const exitsAlready = await user.exitsAlready();

        if (exitsAlready) {
            sessionFlash.flashDataToSession(
                req, 
                {
                    errorMessage: 'User exists already! Try logging in instead!',
                    ...enteredData,
                }, 
                function () {
                    res.redirect('/signup');
                }
            );
            return;
        }

        await user.signup();
    } catch (error) {
        next(error);
        return;
    }

    res.redirect('/login');
}

function getLogin(req, res) {
    let sessionData = sessionFlash.getSessionData(req);

    if (!sessionData) {
        sessionData = {
            email: '',
            password: ''
        };
    }
    res.render('customer/auth/login', { inputData: sessionData });
}

async function login(req, res, next) {
    const user = new User(req.body.email, req.body.password);
    let exitingUser;
    try {
        exitingUser = await user.getUserWithSameEmail();
    } catch (error) {
        next(error);
        return;
    }

    const sessionErrorData = {
        errorMessage: 
            'Invalid credentials - please double-check ypur email and password!',
        email: user.email,
        password: user.password
    }

    if (!exitingUser) {
        sessionFlash.flashDataToSession(req, sessionErrorData, function () {
                res.redirect('/login');
        })
        return;
    }

    const passwordIsCorrect = await user.hasMatchingPassword(
        exitingUser.password
    );

    if(!passwordIsCorrect) {
        sessionFlash.flashDataToSession(req, sessionErrorData, function () {
            res.redirect('/login');
    })
        return;
    }

    authUtil.createUserSession(req, exitingUser, function() {
        res.redirect('/');
    });
}

function logout(req, res) {
    authUtil.destroyUserAuthSession(req);
    res.redirect('/login');
}

module.exports = {
    getSignup: getSignup,
    getLogin: getLogin,
    signup: signup,
    login: login,
    logout: logout
};