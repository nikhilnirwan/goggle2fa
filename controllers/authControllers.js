const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const AsyncManager = require("../utils/asyncManager");
const TwoFactorError = require("../utils/twoFactorError");

const cookieTokenResponse = (user, statusCode, res) => {
    const token = user.signJwtToken();

    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };
    if (process.env.NODE_ENV === "production") {
        cookieOptions.secure = true;
    }
    // user.password = undefined;
    // user.twoFactorAuthCode = undefined;

    res.status(statusCode).cookie("facade", token, cookieOptions).json({
        message: "success",
        token,
        data: {
            user,
        },
    });
};
// generate speakeasy secret code
const generateSpeakeasySecretCode = (email) => {
    const secretCode = speakeasy.generateSecret({
        length: 20,
        name: `${process.env.TWO_FACTOR_APP_NAME} (${email})`,
    });
    return {
        otpauthUrl: secretCode.otpauth_url,
        base32: secretCode.base32,
    };
};

// return QRCode
const returnQRCode = (data, res) => {
    QRCode.toFileStream(res, data);
};

// Check if 2 factor is turned on or not
exports.generate2FACode = async (req, res, next) => {
    const { token, email } = req.body; //req.cookies.facade;
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const { otpauthUrl, base32 } = generateSpeakeasySecretCode(email);
    await User.findOneAndUpdate(
        { _id: decoded.id },
        { "google2FA.accessToken": base32 }
    );
    returnQRCode(otpauthUrl, res);
};
// verify and turn on 2FA. return new token
exports.verify2FACode = async (req, res, next) => {
    const { token, jwtToken } = req.body;
    const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET_KEY);
    const user = await User.findOne({ _id: decoded.id });
    const verified = speakeasy.totp.verify({
        secret: user.google2FA.accessToken,
        encoding: "base32",
        token,
    });
    if (verified) {
        const result = await User.findOneAndUpdate(
            { _id: decoded.id },
            {
                "google2FA.enable": true,
            }
        );
        cookieTokenResponse(result, 200, res);
    } else {
        res.json({
            verified: false,
        });
    }
};

// $-title   Register User
// $-path    POST /api/v1/register
// $-auth    Public
exports.registerUser = AsyncManager(async (req, res, next) => {
    const { name, email, password, confirmPassword } = req.body;
    const newUser = await User.create({
        name,
        email,
        password,
        confirmPassword,
    });

    cookieTokenResponse(newUser, 201, res);
});

// $-title   Login User
// $-path    POST /api/v1/login
// $-auth    Public
exports.loginUser = AsyncManager(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(
            new TwoFactorError("Please provide and email and password!", 400)
        );
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new TwoFactorError("Incorrect email or password", 401));
    }

    if (user.google2FA.enable) {
        res.send({
            "google2FA.enable": true,
        });
    } else {
        cookieTokenResponse(user, 200, res);
    }

    cookieTokenResponse(user, 200, res);
});

// $-title   Logout User
// $-path    POST /api/v1/logout
// $-auth    Public
exports.logoutUser = AsyncManager(async (req, res, next) => {
    res.cookie("facade", "loggedOut", {
        expires: new Date(Date.now + 10 * 1000),
        httpOnly: true,
    });
    res.status(200).json({ message: "success" });
});
