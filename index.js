const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
require("dotenv").config();
const cors = require("cors");
const flash = require("connect-flash");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const SibApiV3Sdk = require("sib-api-v3-sdk");
const crypto = require('crypto');
const Razorpay = require('razorpay');
const passwordValidator = require('password-validator');
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const stripe = require('stripe')(process.env.STRIPE_SECRET)
// Create a schema
var schema = new passwordValidator();

// Add properties to it
schema
  .is()
  .min(8) // Minimum length 8
  .is()
  .max(100) // Maximum length 100
  .has()
  .uppercase() // Must have uppercase letters
  .has()
  .lowercase() // Must have lowercase letters
  .has()
  .digits(1)
  .has()
  .symbols();


const apiKey = defaultClient.authentications["api-key"];
apiKey.apiKey = process.env.API_KEY;

const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();

const app = express();

const instance = new Razorpay({
  key_id: process.env.KEY_ID,
  key_secret: process.env.KEY_SECRET,
});


app.use(express.static("public"));
app.set("view engine", "ejs");


app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(cors());
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

const uri = process.env.LOGIN_URL;

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
});

mongoose.set("useCreateIndex", true);
const connection = mongoose.connection;
connection.once("open", () => {
  console.log("Mongodb connection Established");
});


const userSchema = new mongoose.Schema({
  username: {
    type: String,
    index: true,
    unique: true
  },
  password: String,
  googleId: String,
  phoneNumber: Number,
  fName: String,
  lName: String,
  isVerified: {
    type: Boolean,
    default: false
  },
});

var handleE11000 = function (error, res, next) {
  if (error.name === 'MongoError' && error.code === 11000) {
    console.log(res);
    next(new Error(error.keyValue.username + ' is already registered with us.'));
  } else {
    next();
  }
};

userSchema.post('save', handleE11000);
userSchema.post('update', handleE11000);
userSchema.post('findOneAndUpdate', handleE11000);
userSchema.post('insertMany', handleE11000);

userSchema.plugin(passportLocalMongoose, {
  selectFields: "username password googleId fName lName phoneNumber isVerified",
});
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

var tokenSchema = new mongoose.Schema({
  _userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User",
  },
  token: {
    type: String,
    required: true,
  },
  expireAt: {
    type: Date,
    default: Date.now,
    index: {
      expires: 60 * 60 * 1000,
    },
  },
});

const Token = mongoose.model("Token", tokenSchema);

var forgotPasswordTokenSchema = new mongoose.Schema({
  _userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User",
  },
  token: {
    type: String,
    required: true
  },
  expireAt: {
    type: Date,
    default: Date.now,
    index: {
      expires: 10 * 60 * 1000
    },
  },
});

const ForgotPasswordToken = mongoose.model(
  "ForgotPasswordToken",
  forgotPasswordTokenSchema
);

//Everything about course Schema 

const courseSchema = new mongoose.Schema({
  courseId: {
    type: String,
    required: true
  },
  heading: String,
  shortinfo: String,
  info: String,
  language: String,
  duration: String,
  price: Number,
  priceType: String,
  modulesno: Number,
  courseContent: [String],
  Instructor: String,
});

const Course = mongoose.model("Course", courseSchema);

const userSpecificCourseSchema = new mongoose.Schema({
  _userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User",
  },
  coursesPurchased: [courseSchema],
});

const UserSpecificCourse = mongoose.model("UserSpecificCourse", userSpecificCourseSchema);

const BugBountyHunter = new Course({
  courseId: 'THT101',
  heading: 'Bug Bounty Hunter full length course',
  shortinfo: 'Learn Bug finding techniques with manual and advance methods',
  info: 'Beginner to advance level Bug Bounty. Be a professional Bug bounty hunter and thrive into new exiting field of bug bounty.',
  language: 'English',
  duration: '22 hours',
  price: '999',
  priceType: 'INR',
  modulesno: '20'
});

// BugBountyHunter.save();

var paymentdone = 1;
app.get("/buynow_razorpay_after_success", function (req, res) {
  if (paymentdone) {
    userSpecificCourseSchema.course.push(BugBountyHunter);
  }
})

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy({
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets" || "https://evening-sea-19660.herokuapp.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({
          googleId: profile.id,
          username: profile.emails[0].value,
          fName: profile.name.givenName,
          lName: profile.name.familyName,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function (req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/landing_page");
  }
);

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("landing_page")
  } else {
    res.render("home");
  }

});

app.get("/login", (req, res) => {
  res.render("login", {
    message: req.flash("info")
  });
});

app.get("/register", (req, res) => {
  res.render("signup", {
    message: req.flash("info")
  });
});

app.get("/forgot-password", (req, res) => {
  res.render("fg_password", {
    message: req.flash("info")
  });
});

app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

app.get("/landing_page", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("landing_page", {
      user: req.user
    });
  } else {
    res.render("home");
  }
});

app.get("/courses", (req, res) => {
  res.render("lms", {
    message: req.flash("info")
  })
});

app.get("/lmsPage", (req, res) => {

  res.render("lms_page_two", {
    message: req.flash("info")
  });

});

app.get("/allcourse", function (req, res) {
  Course.find({}, (err, courses) => {
    res.render("allCourses", {
      courses: courses
    });
  });
});

app.get("/payment-page/:courseId", (req, res) => {
  Course.findOne({courseId: req.params.courseId}, (err, course) => {
    if (req.user) {
      res.render("payment_page", {
        user: req.user, course: course
      });
    } else {
      res.redirect('/register');
    }
  });
});

app.get("/checkout-card/:courseId", (req, res) => {
  Course.findOne({courseId: req.params.courseId}, (err, course) => {
    res.render("checkout-card", {user: req.user, course: course});
  })
});

app.post("/create-payment-intent", async (req, res) => {
  // Create a PaymentIntent with the order amount and currency
  const paymentIntent = await stripe.paymentIntents.create({
    amount: 999 * 100,
    currency: "inr",
    description: 'THT101'
  });
  res.send({
    clientSecret: paymentIntent.client_secret
  });
});

app.get('/verify/:paymentId', async (req, res) => {
  const paymentId = req.params.paymentId;
  const paymentIntent = await stripe.paymentIntents.retrieve(
    paymentId
  );
  if (paymentId === paymentIntent.id && req.user.username === paymentIntent.receipt_email) {
    UserSpecificCourse.findOne({
      _userId: req.user._id
    }, (err, userCourses) => {
      Course.findOne({
        courseId: paymentIntent.description
      }, (err, course) => {
        if (userCourses) {
          userCourses.coursesPurchased.push(course);
          userCourses.save();
        } else if (!userCourses) {
          userCourses = new UserSpecificCourse({
            _userId: req.user._id,
            coursesPurchased: [course]
          });
          userCourses.save();
        }
        res.redirect('/course/'+paymentIntent.description);
      });
    });
  }
});

app.get("/course/:description",(req,res,next) => {
  const {description} = req.params;
  const userId = req.session.passport.user;
  UserSpecificCourse.findOne({_userId: userId}, (err, userCourses) => {
    const course = userCourses.coursesPurchased.find(course => course.courseId === description)
    if(course !== undefined){
      res.render('course');
    }
  });
});

app.get("/payments-razorpay", (req, res) => {
  res.render("payment", {
    key: process.env.KEY_ID
  });
});

app.get("/confirmation/:email/:token", (req, res) => {
  Token.findOne({
      token: req.params.token,
    },
    function (err, token) {
      // token is not found into database i.e. token may have expired
      if (!token) {
        req.flash(
          "info",
          "Your verification link may have expired. Please click on resend for verify your Email."
        );
        res.redirect("/login");
      }
      // if token is found then check valid user
      else {
        User.findOne({
            _id: token._userId,
            username: req.params.email,
          },
          function (err, user) {
            // user is already verified
            if (user.isVerified) {
              req.flash("info", "User has been already verified. Please Login");
              res.redirect("/login");
            }
            // verify user
            else {
              // change isVerified to true
              user.isVerified = true;
              user.save(function (err) {
                // error occur
                if (err) {
                  return res.status(500).send({
                    msg: err.message,
                  });
                }
                // account successfully verified
                else {
                  res.redirect("/login");
                }
              });
            }
          }
        );
      }
    }
  );
});

app.get("/reset/password/:email/:token", (req, res) => {
  ForgotPasswordToken.findOne({
      token: req.params.token
    },
    function (err, resetPasswordToken) {
      // token is not found into database i.e. token may have expired
      if (!resetPasswordToken) {
        req.flash(
          "info",
          "Your reset password token may have expired. Please click on forgot password to try again."
        );
        res.redirect("/fg_password");
      }
      // if token is found then check valid user
      else {
        User.findOne({
            _id: resetPasswordToken._userId,
            username: req.params.email
          },
          function (err, user) {
            // not valid user
            if (!user) {
              req.flash(
                "info",
                "We were unable to find a user for this link. Please SignUp!"
              );
              res.redirect("/register");
            }
            // send the reset password page for the user that is not logged in
            else {
              if (req.user) {
                req.flash(
                  "info",
                  "You are already logged in, Please check reset password for changing your password"
                );
                res.redirect("/landing_page");
              } else {
                res.render("reset", {
                  token: resetPasswordToken.token,
                  email: user.username,
                  message: req.flash('info')
                });
              }
            }
          }
        );
      }
    }
  );
});

app.post('/register', (req, res) => {
  User.findOne({
    username: req.body.username
  }, (user, err) => {
    if (!err) {
      if (!user) {
        if (schema.validate(req.body.password)) {
          User.register({
              username: req.body.username,
              fName: req.body.fName,
              lName: req.body.lName,
              phoneNumber: req.body.number,
            },
            req.body.password,
            function (err, user) {
              if (err) {
                console.log(err);
                res.redirect('/register');
              }
              // generate  token and save
              var token = new Token({
                _userId: user._id,
                token: crypto.randomBytes(16).toString('hex'),
              });
              token.save(function (err) {
                if (err) {
                  return res.status(500).send({
                    msg: err.message,
                  });
                }
                // mail configuration for sendinblue
                sendSmtpEmail = {
                  to: [{
                    email: req.body.username,
                  }, ],
                  sender: {
                    email: process.env.ACCOUNT,
                  },
                  subject: 'email verification',
                  htmlContent: '<h1>Hello</h1> <a href="https://' +
                    req.headers.host +
                    '/confirmation/' +
                    user.username +
                    '/' +
                    token.token +
                    '">Click here to verify</a><p>If the link does not work then please copy the code given below in the browser</p>' +
                    '<p>http://' +
                    req.headers.host +
                    '/confirmation/' +
                    user.username +
                    '/' +
                    token.token +
                    '</p>',
                  headers: {
                    'api-key': process.env.API_KEY,
                    'content-type': 'application/json',
                    accept: 'application/json',
                  },
                };
                apiInstance.sendTransacEmail(sendSmtpEmail).then(
                  function (data) {
                    console.log('API called successfully. Returned data: ' + data);
                    res.render('cnf_email')
                  },
                  function (error) {
                    console.error(error);
                  }
                );
              });
            }
          );
        } else {
          req.flash('info', 'Your password does not meet all the conditions, Please try again!');
          res.redirect('/register');
        }
      } else {
        req.flash('info', 'This email address is already associated with another account, Please Login!');
        res.redirect('/register');
      }
    } else {
      req.flash('info', 'This email address is already associated with another account, Please Login!');
      res.redirect('/register');
    }
  });
});

app.post("/login", (req, res) => {
  User.findOne({
    username: req.body.username
  }, (err, user) => {
    if (err) {
      console.log(err);
      return res.status(500).send({
        msg: err.message,
      });
    } else if (!user) {
      req.flash(
        "info",
        "This email is not registered with any account. Please sign up!"
      );
      res.redirect("/login");
    } else if (user.googleId) {
      req.flash(
        "info",
        "Your account is linked with google please login with google to continue"
      );
      res.redirect("/login");
      // } else if (!user.isVerified) {
      //   req.flash(
      //     "info",
      //     "Your Email has not been verified. Please click on resend"
      //   );
      //   res.redirect("/login");
      // } 
    } else {
      const user1 = new User({
        password: req.body.password,
        username: req.body.username,
      });
      req.logIn(user1, function (err) {
        if (err) {
          console.log(err);
          res.redirect('/login');
        } else {
          req.flash('info', 'Incorrect password or Email');
          passport.authenticate('local', {
            failureRedirect: '/login'
          })(req, res, function () {
            res.redirect('/landing_page');
          });
        }
      });
    }
  });
});

app.post("/api/payment/order", (req, res) => {
  params = req.body;
  instance.orders
    .create(params)
    .then((data) => {
      res.send({
        sub: data,
        status: "success"
      });
    })
    .catch((error) => {
      res.send({
        sub: error,
        status: "failed"
      });
    });
});

app.post("/api/payment/verify", (req, res) => {
  body = req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;

  var expectedSignature = crypto
    .createHmac("sha256", process.env.KEY_SECRET)
    .update(body.toString())
    .digest("hex");
  console.log("sig" + req.body.razorpay_signature);
  console.log("sig" + expectedSignature);
  var response = {
    status: "failure"
  };
  if (expectedSignature === req.body.razorpay_signature)
    response = {
      status: "success"
    };
  res.send(response);
});

app.post("/forgot-password", function (req, res) {
  User.findOne({
    username: req.body.username
  }, function (err, user) {
    // check if the user exists
    if (!user) {
      req.flash(
        "info",
        "We were unable to find a user with that email. Make sure your Email is correct!"
      );
      res.redirect("/forgot-password");
    }
    //user is registered with google account
    else if (user.googleId) {
      req.flash(
        "info",
        "Your account is linked with google please login with google to continue"
      );
      res.redirect("/login");
    } else {
      var forgotPasswordToken = new ForgotPasswordToken({
        _userId: user._id,
        token: crypto.randomBytes(20).toString("hex"),
      });
      forgotPasswordToken.save(function (err) {
        if (err) {
          return res.status(500).send({
            msg: err.message
          });
        }
        // Send email (use credintials of GMAIL)

        sendSmtpEmail = {
          to: [{
            email: user.username
          }],
          sender: {
            email: process.env.ACCOUNT,
          },
          subject: "RESET PASSWORD LINK",
          htmlContent: "<h1>Hello " +
            user.fName +
            "</h1>" +
            '<a href="https://' +
            req.headers.host +
            "/reset/password" +
            user.username +
            "/" +
            forgotPasswordToken.token +
            '">Click here to reset password</a>' +
            "<p>if the above given link is not working, please copy this in your browser:</p>" +
            "<p>http://" +
            req.headers.host +
            "/reset/password/" +
            user.username +
            "/" +
            forgotPasswordToken.token +
            "</p>",
          headers: {
            "api-key": process.env.API_KEY,
            "content-type": "application/json",
            accept: "application/json",
          },
        };
        apiInstance.sendTransacEmail(sendSmtpEmail).then(
          function (data) {
            console.log("mail sent successfully");
            req.flash(
              "info",
              "Please check your email, a link has been sent to the given email address"
            );
            res.redirect("/forgot-password");
          },
          function (error) {
            console.error(error);
          }
        );
      });
    }
  });
});

app.post('/reset-password/:email/:token', (req, res) => {
  if (schema.validate(req.body.password)) {
    User.findByUsername(req.params.email).then((user) => {
        if (user) {
          user.setPassword(req.body.password, function () {
            user.save();
            res.redirect('/login');
            ForgotPasswordToken.findOneAndDelete({
              token: req.params.token
            });
          });
        } else {
          res.status(500).json({
            message: 'This user does not exist'
          });
        }
      }),
      function (err) {
        console.error(err);
      };
  } else {
    req.flash('info', 'Your password does not meet all the conditions, please try again.');
    res.redirect('/reset/password/' + req.params.email + '/' + req.params.token);
  }
});

app.post("/resend-link", (req, res) => {
  User.findOne({
      username: req.user.username,
    },
    function (err, user) {
      if (user.googleId) {
        req.flash(
          "info",
          "Your account is linked with google please login with google to continue"
        );
        res.redirect("/login");
      }
      // send verification link
      else {
        // generate token and save
        var token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString("hex"),
        });
        token.save(function (err) {
          if (err) {
            return res.status(500).send({
              msg: err.message,
            });
          }

          // Send email using sendinblue
          sendSmtpEmail = {
            to: [{
              email: req.user.username,
            }, ],
            sender: {
              email: process.env.ACCOUNT,
            },
            subject: "email verification",
            htmlContent: '<h1>Hello</h1> <a href="https://' +
              req.headers.host +
              "/confirmation/" +
              user.username +
              "/" +
              token.token +
              '">Click here to verify</a><p>If the link does not work then please copy the code given below in the browser</p>' +
              "<p>http://" +
              req.headers.host +
              "/confirmation/" +
              user.username +
              "/" +
              token.token +
              "</p>",
            headers: {
              "api-key": process.env.API_KEY,
              "content-type": "application/json",
              accept: "application/json",
            },
          };
          apiInstance.sendTransacEmail(sendSmtpEmail).then(
            function (data) {
              console.log("API called successfully. Returned data: " + data);
              req.logout();
              req.flash("info", "Please check your mail");
              res.redirect("/login");
            },
            function (error) {
              console.error(error);
            }
          );
        });
      }
    }
  );
});

app.listen(process.env.PORT || 3000, function () {
  console.log("server is running on 3000");
});