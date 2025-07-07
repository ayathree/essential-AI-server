const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion } = require('mongodb');
 require('dotenv').config();
 const validator= require('validator');
 const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
 const port = process.env.PORT || 5000;
 
 const app = express();
 const corsOptions = {
  origin : ['http://localhost:5173', 'http://localhost:5174', 'https://essential-ai-client.vercel.app'],
  credentials : true,
  optionSuccessStatus : 200,

 }

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser())



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ycbv1lf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // database collection
    const userCollection = client.db('essential').collection('users')

     // jwt token
       const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });
};


app.post('/registration', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Enter valid email" });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }
    
    // Check if user exists
    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    
    // Hash password
    const hashPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const newUser = { 
      name, 
      email, 
      password: hashPassword,
      createdAt: new Date() 
    };
    
    const result = await userCollection.insertOne(newUser);
    const user = result.ops ? result.ops[0] : newUser; // Handle different MongoDB driver versions
    
    // Generate token
    const token = generateToken(user._id);
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // Return response (don't send back password hash)
    const userResponse = {
      _id: user._id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt
    };
    
    return res.status(201).json(userResponse);
    
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Find user
    const user = await userCollection.findOne({ email });
    if (!user) {
      // Don't reveal whether user exists for security
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate token
    const token = generateToken(user._id);

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return minimal user info (without sensitive data)
    const userResponse = {
      _id: user._id,
      name: user.name,
      email: user.email
    };

    return res.status(200).json({ 
      message: "Login successful",
      user: userResponse
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// clear cookie
app.get('/logout', async(req,res)=>{
 try{
  res.clearCookie('token', {
   httpOnly: true,
   secure: process.env.NODE_ENV === 'production',
   sameSite: process.env.NODE_ENV === 'production'?'none':'strict',
   maxAge:0,
 })
 return res.status(200).json({ 
      message: "Logout successfully",
    });
 }
 catch(error){
  console.error("Logout error:", error);
    return res.status(500).json({ message: "logout server error" });

 }
})
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);



app.get('/', (req,res)=>{
    res.send('essential running')
});

app.listen(port, ()=>{
    console.log(`essential is running on port: ${port}`)
})