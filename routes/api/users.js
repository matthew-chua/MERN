const express = require("express");
const router = express.Router();
const { check, validationResult } = require("express-validator");
const gravatar = require("gravatar");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const config = require("config");

const User = require("../../models/User");

//@route POST api/users
//@desc register a new user
//@access public
router.post(
  "/",
  //this is for validation
  [
    check("name", "Name is required!").not().isEmpty(),
    check("email", "Please enter a valid email address.").isEmail(),
    check(
      "password",
      "Please enter a password that is more than 6 characters"
    ).isLength({ min: 6 }),
  ], 
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { name, email, password } = req.body;

    try {

        //see if user exists

      let user = await User.findOne({email});

      if (user) {
          return res.status(400).json({errors: [{msg: "User already exists"}]})
      }
      //get gravatar

      const avatar = gravatar.url(email, {
          s: "200",
          r: "pg",
          d: 'mm',
      })

      user = new User({
          name,
          email,
          avatar,
          password
      })

      //encrypt password

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      //return jwt

      const payload = {
          user: {
              id: user.id
          }
      }

      jwt.sign(
          payload,
          config.get("jwtToken"),
          { expiresIn: 360000 },
          (err, token) => {
              if (err) throw err;
              res.json({ token });
              res.send(token);
          }
      )

    } catch(err) {
        console.error(err.message);
        res.status(500).send("server error")
    }
  }
);

module.exports = router;
