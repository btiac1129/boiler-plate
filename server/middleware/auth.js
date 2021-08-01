const { User } = require("../models/User");

let auth = (req, res, next) => {
    // 인증 처리를 하는 곳
    // 클라이언트 쿠키에서 토큰을 가져온다. (cookie-parser 이용)
    let token = req.cookies.x_auth;
    // 토큰을 복호화한 후 유저를 찾는다. (User 모델에서 methods 만들어서 하면 된다.)
    User.findByToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json({ isAuth: false, error: true });
        // reqeust에 token, user 넣어줘서 index 라우팅에서 사용 가능.
        req.token = token;
        req.user = user;
        // middleware 탈출
        next();
    });
    // 유저가 있으면 인증 Okay
    // 유저가 없으면 인증 No
};

module.exports = { auth };