import express from "express";
import pg from "pg";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const port = 3000;
const saltRounds = 10;
const secretKey = "SECRETWORD";
let uName ="";
//let user;
const db = new pg.Client({
    user : "postgres",
    host : "localhost",
    database : "Users",
    password : "123456",
    port : 5432
})

db.connect();

app.use(bodyParser.urlencoded({extended : true}));
// app.use(authorizedToken);

app.get("/", (req, res) => {
    res.render("index.ejs");
    
});

app.get("/user/logout", (req, res) => {
    res.clearCookie("token"); // clear the cookie
    res.render("index.ejs");
});

app.get("/user/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/user/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/user/dashboard", authorizedToken, async (req, res) => {

    try{
        const userData = req.payload;
        console.log("User data : ", userData.username);
        const uName = await db.query('SELECT name FROM userrecords WHERE email = $1', [userData.username]);
         console.log(uName);
        res.render("dashboard.ejs", {user : uName.rows[0].name, email : userData.username});
        
    }
    catch(err){
        return res.status(401).json({error : err});
    }
    
});
// app.get("/user/dashboard", (req, res) => {
//     res.render("dashboard.ejs", { user : uName});
// });

app.get("/user/otp", async (req, res) => {
    // const otp = otpGenerator();
    // console.log("email :", req.query.email);
    // res.send(`GET Email: ${req.query.email}`);
    const enteredOtp = req.body.otp;
    const Email = req.query.email;
    console.log("Entered otp : ", enteredOtp);
    res.render("otpFile.ejs",{email : Email });//, {otp : otp});
});

app.get("/user/update", async (req, res) => {
    const uEmail = req.query.email;
    console.log("UEMAIL   :", uEmail);
    res.render("update.ejs",{email : uEmail});
});

app.get("/user/delete", async (req, res) => {
    const uEmail = req.query.email;

    try{
        await db.query("DELETE FROM userrecords WHERE email = $1", [uEmail]);
        res.redirect("/user/login");
    }
    catch(err){
        res.json({Error : "Error in deleting the record"});
    }
});

app.post("/user/otp/", async(req, res) => {
    // console.log("email :", res.params.email);
    // console.log("OTP   :", otp);
    let errors = [];
    const email = req.body.email;
    console.log("Email :", email);
    const enteredOtp = req.body.otp;
    const user = await db.query("Select * from userrecords WHERE email = $1", [email]);
    console.log(user.rows[0]);
    const storedOtp = user.rows[0].otp;


    if(storedOtp === enteredOtp)
        res.render("login.ejs", {message : "Account created, Please log in"});
    else{
        await db.query("DELETE FROM userrecords WHERE email = $1", [email]);
        errors.push({message : "OTP not verified, Please try again"});
        res.render("register.ejs", {errors});
    }
    
})

app.post("/user/register", async (req, res) => {
    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;
    let enteredEmail =""
    const otp = otpGenerator();
   // console.log(name, email, password);
    let errors = [];

    try{
        enteredEmail = await db.query('SELECT email FROM userRecords where email = $1', [email]);

        console.log(enteredEmail);
        if(!name || !email || !password){
            errors.push({message : "Please fill all the fieds"});
        }
        if(password.length < 6){
            errors.push({message : "Password length atleast 6 characters"});
        }

        if(enteredEmail.rows.length > 0)
            errors.push({message : "Email already exists"});
            
        if(errors.length !== 0){
            res.render("register.ejs", {errors});
        }    
        else{
            //  res.redirect("/user/otp");
            // Password Hashing
            bcrypt.hash(password, saltRounds, async (err, hashedPassword) => {
                if(err)
                    console.log(err);

                await db.query('Insert into userRecords(name, email, password,otp) values($1, $2, $3, $4)',[name, email, hashedPassword, otp]);
                // res.render("login.ejs");
                console.log("otp  :", otp);
                res.redirect(`/user/otp?email=${email}`);

            }); 

            // const payload = {
            //     username : email,
            //     password : password
            // };

            // const token = generateJwtToken(payload);
            // console.log(token);
           // res.json({token});
        }
    }
    catch(err){
        console.log(err);
    }
      
});

app.post("/user/login", async (req, res) => {
    console.log("***********");
    const uEmail = req.body.username;
    const loginPassword = req.body.password;
    
    try{
        const results = await db.query('SELECT * from userrecords where email = $1',[uEmail]);

        if(results.rows.length > 0){
            const user = results.rows[0];
            const storedHashedPass = user.password;
            //console.log(storedHashedPass);

            bcrypt.compare(loginPassword, storedHashedPass, (err, result) => {
                if(err)
                    console.log("Error in password matching :", err);

                else{
                    if(result){

                        const payload = {
                            username : user.email,
                            password : user.password
                        };

                        const token = generateJwtToken(payload);
                        console.log(token);
                        
                        res.cookie("token", token);
                        res.redirect(`/user/dashboard?token=${token}`);
                         
                    }
                    else{
                        res.render("login.ejs", {message : "Please enter valid username or password"});
                    }
                }
            });
        }
        else    
            // res.send('Incorrect password');
            res.render("login.ejs", {message : "No username exits, Create new account"});
    }
    catch(err){
        res.send("User not found");
    } 
});


app.post("/user/update",async (req, res) => {
    const uEmail = req.body.email;
    const newName = req.body.updatedName;

    try{
    const result = await db.query("SELECT * FROM userrecords WHERE email = $1",[uEmail]);

    if(!result)
        res.json({error : "error in getting the data"});

    await db.query("UPDATE userrecords SET name = $1 WHERE email = $2", [newName, uEmail]);
    const user = result.rows[0];
    console.log("---",user.email);
    // res.redirect("/user/dashboard");

    const payload = {
    username : user.email,
    password : user.password        
    };

    const token = generateJwtToken(payload);
    res.cookie("token", token);

    res.redirect(`/user/dashboard?token=${token}`);
    // res.render("dashboard.ejs", {user : newName});
    // res.redirect("/user/dashboard");
    }
    catch(err){
        res.json({error : err});
    }
    
})

app.listen(port, () => {
    console.log(`Server listen on the port : ${port}`);
});



function authorizedToken(req, res, next) {
    // const authHeader = req.headers.authorization;
    // console.log(req.headers.authorization);

    // if (!authHeader) {
    //     return res.status(401).json({ error: "Unauthorized" });
    // }

    // const token = authHeader.split(' ')[1];
    const token = req.query.token;
    if (!token) 
        return res.status(401).json({ error: "Unauthorized" });

    try {
        // Verify the JWT token
        const decodedTokenData = jwt.verify(token, secretKey);
        //console.log(decodedTokenData);
        req.payload = decodedTokenData;

        next();
    } catch(err) {
        console.log(err);
    }
}


function generateJwtToken(userData){

    return jwt.sign(userData, secretKey,{expiresIn:"1d"});
}

function otpGenerator(){
    const otp = 1000 + Math.floor(Math.random() * 1000);
    return otp;
}