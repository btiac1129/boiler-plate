const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50,
    },
    email: {
        type: String,
        trim: true,
        unique: 1,
    },
    password: {
        type: String,
        minlength: 5,
    },
    lastname: {
        type: String,
        maxlength: 50,
    },
    role: {
        type: Number,
        default: 0,
    },
    image: String,
    token: {
        type: String,
    },
    tokenExp: {
        type: Number,
    },
});

userSchema.pre("save", function(next) {
    var user = this;

    if (user.isModified("password")) {
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if (err) return next(err);

            bcrypt.hash(user.password, salt, function(err, hash) {
                if (err) return next(err);
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
});

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // plainPassword 1234567  ===  암호화된 비밀번호 ?
    // plainPassword를 암호화 해서, DB에 있는 암호화 같은지 확인해야 한다. 복호화 할 수는 없어서.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

userSchema.methods.generateToken = function(cb) {
    var user = this;
    // jsonwebtoken 이용해서 토큰을 생성하기
    var token = jwt.sign(user._id.toHexString(), "secretToken");
    user.token = token;
    user.save(function(err, user) {
        if (err) return cb(err);
        cb(null, user);
    });
};

userSchema.statics.findByToken = function(token, cb) {
    var user = this;
    // 토큰을 decode 한다.
    jwt.verify(token, "secretToken", function(err, decoded) {
        // 유저 아이디(decoded)를 이용해서 유저를 찾은 다음,
        // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인한다.
        user.findOne({ _id: decoded, token: token }, function(err, user) {
            if (err) return cb(err);
            cb(null, user);
        });
    });
};

const User = mongoose.model("User", userSchema);
module.exports = { User };