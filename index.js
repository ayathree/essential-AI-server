const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
 require('dotenv').config();
 const validator= require('validator');
 const cloudinary = require('cloudinary').v2;
 const multer = require('multer');
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

// Configure Cloudinary
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ycbv1lf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Multer config - using memory storage for Cloudinary
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

async function run() {
  try {
    // database collection
    const userCollection = client.db('essential').collection('users')
    const productCollection = client.db('essential').collection('products');

     // jwt token
       const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });
  
};

// jwt token for admin
       const generateToken1 = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });
  
};

// Middleware should be defined separately (not inside route handler)
const isAuth = async (req, res, next) => {
  try {
    const { token } = req.cookies;
    if (!token) {
      return res.status(401).json({ message: "Authentication required" });
    }
    
    const verifyToken = jwt.verify(token, process.env.JWT_SECRET);
    if (!verifyToken) {
      return res.status(401).json({ message: "Invalid token" });
    }
    
    req.userId = verifyToken.userId;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(500).json({ message: "Authentication failed" });
  }
};

// middleware for admin
const isAuthAdmin = async (req, res, next) => {
  try {
    const { token } = req.cookies;
    if (!token) {
      return res.status(401).json({ message: "Authentication required" });
    }
    
    const verifyToken = jwt.verify(token, process.env.JWT_SECRET);
    if (!verifyToken) {
      return res.status(401).json({ message: "Invalid token" });
    }
    
    req.adminEmail = process.env.ADMIN_EMAIL;
    next();
  } catch (error) {
    console.error("Admin Authentication error:", error);
    return res.status(500).json({ message: "Admin Authentication failed" });
  }
};

// Route handler
app.get('/getCurrentUser', isAuth, async (req, res) => {
  try {
    // Correct MongoDB query - findById and proper projection
    const user = await userCollection.findOne({ _id: new ObjectId(req.userId) });
// Then manually remove password
     delete user.password
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    return res.status(200).json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        // Add other non-sensitive fields as needed
      }
    });
    
  } catch (error) {
    console.error("Get current user error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Failed to fetch user data" 
    });
  }
});

// Admin route handle
app.get('/getAdmin', isAuthAdmin, async (req, res) => {
  try {
    // Correct MongoDB query - findById and proper projection
    const adminEmail = req.adminEmail
    
    if (!adminEmail) {
      return res.status(404).json({ message: "Admin not found" });
    }
    
    return res.status(200).json({
      email:adminEmail,
      role:"admin"
    });
    
  } catch (error) {
    console.error("Get admin error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Failed to fetch admin data" 
    });
  }
});


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
        sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
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
        sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
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

// admin login
app.post('/adminSignin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
      // Generate token
    const token = generateToken1(email);

    // Set secure cookie
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
      });

    // Return minimal user info (without sensitive data)
    // const userResponse = {
    //   _id: user._id,
    //   name: user.name,
    //   email: user.email
    // };

    return res.status(200).json({ 
      message: "Login successful",
      token: token
    });
      
    }

    return res.status(400).json({message:"Invalid Credentials"})

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



// product add
app.post('/products', upload.array('images', 4), async (req, res) => {
      try {
        const { name, price, description, category, subCategory, sizes, bestseller } = req.body;
        const files = req.files; // Array of files

        if (!files || files.length === 0) {
          return res.status(400).json({ error: 'At least one image is required' });
        }

        // Upload images to Cloudinary
        const uploadPromises = files.map(file => {
          return new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
              {
                folder: 'essential-products',
                resource_type: 'auto'
              },
              (error, result) => {
                if (error) reject(error);
                else resolve(result);
              }
            );
            
            uploadStream.end(file.buffer);
          });
        });

        const cloudinaryResults = await Promise.all(uploadPromises);

        // Create product document
        const productData = {
          name,
          price: parseFloat(price),
          description,
          category,
          subCategory,
          sizes: JSON.parse(sizes),
          bestseller: bestseller === "true",
          images: cloudinaryResults.map(result => ({
            public_id: result.public_id,
            url: result.secure_url,
            width: result.width,
            height: result.height
          })),
          createdAt: new Date(),
          updatedAt: new Date()
        };

        // Insert into MongoDB
        const result = await productCollection.insertOne(productData);

        res.status(201).json({
          success: true,
          product: {
            id: result.insertedId,
            ...productData
          }
        });

      } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).json({ 
          success: false,
          error: 'Failed to add product',
          message: error.message
        });
      }
    });
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