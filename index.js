const express = require("express");
const cors = require("cors");
require("./db/config");
const User = require("./db/User");

const Jwt=require('jsonwebtoken');
const jwtKey='internship';

const app = express();
app.use(express.json());
app.use(cors());

app.post("/signup", async (req, resp) => {
  let user = new User(req.body);
  let result = await user.save();
  result= result.toObject();
  delete result.password;
  Jwt.sign({result},jwtKey,{expiresIn:"2h"},(err,token)=>{
    if(err){
      resp.send({ result: "Something went wrong, Please try after sometime" });
    }
    resp.send({result, auth:token});
  })
});

app.post("/login", async (req, resp) => {
  console.log(req.body);
  if (req.body.password && req.body.email) {
    let user = await User.findOne(req.body).select("-password");
    if (user) {
      Jwt.sign({user},jwtKey,{expiresIn:"2h"},(err,token)=>{
        if(err){
          resp.send({ result: "Something went wrong, Please try after sometime" });
        }
        resp.send({user, auth:token});
      })
      
    } else {
      resp.send({ result: "No user found" });
    }
  }
  else{
    resp.send({ result: "No user found" });
  }

});

// we cannot use token with signUp and login api but for another apis such as search , add , delete product tokens are added

function verifyToken(req,resp,next){
  const token=req.headers['authorization'];
  if(token){
    token=token.split(' ')[1];
    console.warn("middleware called if",token);
    Jwt.verify(token, jwtKey,(err, valid)=>{
      if(err){
        resp.status(401).send({result: "Please provide valid token "});
      }
      else{
        next();
      }

    })
  }
  else{
    resp.status(403).send({result: "Please add token with header "});
  }
  console.warn("middleware called",token);
  next();
}

app.listen(3000);
