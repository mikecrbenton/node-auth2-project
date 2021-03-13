const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model")
const bcrypt = require("bcryptjs") // IMPORT BCRYPT
const jwt = require("jsonwebtoken")

const restricted = async (req, res, next) => {
/*=========================================================================================
   If the user does not provide a token in the Authorization header:
   status 401 { "message": "Token required" }

   If the provided token does not verify:
   status 401 { "message": "Token invalid" }

   Put the decoded token in the req object, to make life easier for middlewares downstream!
===========================================================================================*/  
		try {
         // GET THE TOKEN VALUE FROM A MANUAL REQUEST "HEADER" 
         const token = req.headers.authorization
         // CHECK NOT EMPTY
         if(!token) {
            return res.status(401).json({ message: "Token required"})
         }
         // VERIFY SIGNATURES MATCH - DIDN'T CHANGE
         jwt.verify(token, JWT_SECRET, (err,decoded)=>{
            // TOKEN DIDN'T VERIFY
            if(err){
               return res.status(401).json({ message:"Token invalid"})
            }
            req.token = decoded
            next() 
         })
		} catch(err) {
			next(err)
		}
}

//                     0          1         2
// const roles = ["student","instructor","admin"] // NEED TO BE IN THE PROPER ORDER FOR ACCESS

const only = (role_name) => (req, res, next) => {

/*=========================================================================================
   If the user does not provide a token in the Authorization header with a role_name
   inside its payload matching the role_name passed to this function as its argument:
   status 403 { "message": "This is not for you" }

   Pull the decoded token from the req object, to avoid verifying it again!
===========================================================================================*/

   try{
      const token = req.headers.authorization

      jwt.verify(token, process.env.JWT_SECRET, (err,decoded)=>{
         console.log("DECODED:",decoded)
         if(err){
            return res.status(401).json({ message:"Invalid Credentials"})
         }
         if( decoded.role_name !== role_name ){
            return res.status(403).json({message:"This is not for you"})
         }
         req.token = decoded

         next() 
      })
   }catch(err){
      next(err)
   }
}


const checkUsernameExists = async (req, res, next) => {

      try{
         const user = await Users.findBy(req.body.username).first()

         if (!user) {
            return res.status(422).json({message:"Invalid credentials"})
         }
         next()

      }catch(err) {
         next(err)
      }
}


const validateRoleName = (req, res, next) => {
  /*=========================================================================================
    - If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    - If role_name is missing from req.body, or if after trimming it is just an empty string,
      set req.role_name to be 'student' and allow the request to proceed.

    - If role_name is 'admin' after trimming the string:
      status 422 { "message": "Role name can not be admin" }

    - If role_name is over 32 characters after trimming the string:
      status 422 { "message": "Role name can not be longer than 32 chars" }
  ===========================================================================================*/
  try{
      let role_name = req.body.role_name

      if( !role_name ){
         return res.status(422).json({message:"Need to enter a role name"})
      }
      // TRIM ANY WHITESPACE
      role_name = role_name.trim()

      if( role_name === "student" || role_name === "instructor" ){
         req.body.role_name = role_name
         next()
      }
      
      if( role_name.length > 32 ){
         return res.status(422).json({message:"Role name can not be longer than 32 chars"})
      }else if( role_name === "admin"){
         return res.status(422).json({message:"Role name can not be admin"})
      }else if( role_name === ""){
         req.body.role_name = "student"
         next()
      }
  }catch(err){
      next(err)
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
