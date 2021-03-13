const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model")
const bcrypt = require("bcryptjs") // IMPORT BCRYPT
const jwt = require("jsonwebtoken")


router.post("/register", validateRoleName, async (req, res, next) => {
  /**===================================================================================
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   ======================================================================================*/
   try {
      const { username, password, role_name } = req.body

		const newUser = await Users.add({
			username,
			// hash the password with a time complexity of "14"
         password: await bcrypt.hash(password, 14),
         role_name
      })
      
      res.status(201).json(newUser)

	} catch(err) {
		next(err)
	}
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
   try {
		const { username, password } = req.body
		const user = await Users.findBy(username)
		
		if (!user) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}
		// hash the password again and see if it matches what we have in the database
		const passwordValid = await bcrypt.compare(password, user.password)

		if (!passwordValid) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}
      // jwt.sign( payload, secretOrPrivateKey, [options,callback])
      const token = jwt.sign(
         { 
            subject: user.user_id,
            username: user.username,
            role_name: user.role_name, // from joined table ( "roles")
         }, 
         JWT_SECRET
      )
		res.json({
         message: `${user.username} is back!`, 
         token: token // TOKEN IS RETURNED IN THE RESPONSE BODY======
		})
	} catch(err) {
		next(err)
	}
  /**===================================================================================
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   ======================================================================================*/
});

module.exports = router;
