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
    const orderCollection = client.db('essential').collection('orders')

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
    // Clear invalid token
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });
    return res.status(401).json({ message: "Authentication failed" });
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
    if (!verifyToken || !verifyToken.email || verifyToken.email !== process.env.ADMIN_EMAIL) {
      // Clear invalid admin token
      res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, 
      });
      return res.status(401).json({ message: "Admin authentication required" });
    }
    
    req.adminEmail = verifyToken.email;
    next();
  } catch (error) {
    console.error("Admin Authentication error:", error);
    // Clear invalid token on error
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });
    return res.status(401).json({ message: "Admin authentication failed" });
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
    // Use the email from the verified token, not from env
    const adminEmail = req.adminEmail;
    
    if (!adminEmail || adminEmail !== process.env.ADMIN_EMAIL) {
      return res.status(404).json({ message: "Admin not found" });
    }
    
    return res.status(200).json({
      email: adminEmail,
      role: "admin"
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
        sameSite:process.env.NODE_ENV === 'production'?'none':'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, 
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
        sameSite:process.env.NODE_ENV === 'production'?'none':'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, 
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
        sameSite:process.env.NODE_ENV === 'production'?'none':'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, 
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
   sameSite: process.env.NODE_ENV === 'production'?'none':'lax',
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

// product view
app.get('/products', async(req,res)=>{
  const result = await productCollection.find().toArray()
  res.send(result)
})

// product delete
 app.delete('/products/:id',isAuthAdmin, async(req,res)=>{
  const id = req.params.id
  const query = {_id : new ObjectId(id)}
  const result =await productCollection.deleteOne(query)
  res.send(result)
})

// add to cart
app.post('/addToCart', isAuth, async (req, res) => {
  try {
    const { itemId, size } = req.body; // No need for userId in body
    const userId = req.userId; // From isAuth middleware

    // 1. Find the user
    const userData = await userCollection.findOne({ _id: new ObjectId(userId) });
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }

    // 2. Initialize or update cartData
    const cartData = userData.cartData || {};
    
    if (cartData[itemId]) {
      cartData[itemId][size] = (cartData[itemId][size] || 0) + 1;
    } else {
      cartData[itemId] = { [size]: 1 };
    }

    // 3. Update the user document
    await userCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { cartData } }
    );

    return res.status(201).json({ message: "Added To Cart" });
  } catch (error) {
    console.error("AddToCart Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// update cart
app.put('/updateCart', isAuth, async (req, res) => {
  try {
    const userId = req.userId; 
    const { itemId, size, quantity } = req.body;

    // 1. Validate input
    if (!itemId || !size || quantity === undefined || quantity < 0) {
      return res.status(400).json({ message: "Invalid input: itemId, size, and positive quantity required" });
    }

    // 2. Check if user exists
    const userData = await userCollection.findOne({ _id: new ObjectId(userId) });
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }

    // 3. Initialize or validate cartData
    const cartData = userData.cartData || {};
    if (!cartData[itemId]) {
      return res.status(400).json({ message: "Item not found in cart" });
    }

    // 4. Update quantity (full replacement)
    cartData[itemId][size] = quantity;

    // 5. Save to database
    await userCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { cartData } }
    );

    return res.status(200).json({ 
      message: "Cart updated successfully",
      cartData // Optional: Return updated cart
    });

  } catch (error) {
    console.error("Update Cart Error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// get current user
app.post('/cart', isAuth, async (req, res) => {
  try {
    const userId = req.userId; 

    // 1. Find user with proper ObjectId conversion
    const userData = await userCollection.findOne({ 
      _id: new ObjectId(userId) 
    });

    // 2. Handle user not found
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }

    // 3. Return cart data (empty object if doesn't exist)
    const cartData = userData.cartData || {};
    return res.status(200).json(cartData);

  } catch (error) {
    console.error("Get Cart Error:", error);
    
    // Handle invalid ObjectId format
    if (error instanceof TypeError) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    return res.status(500).json({ message: "Failed to fetch cart data" });
  }
});

// place order
app.post('/placeOrder', isAuth, async (req, res) => {
  try {
    const { items, amount, address } = req.body;
    const userId = req.userId; // From isAuth middleware

    // 1. Validate required fields
    if (!items || !amount || !address) {
      return res.status(400).json({ message: "Missing required fields: items, amount, or address" });
    }

    // 2. Create order document
    const orderData = {
      items,
      amount,
      userId: new ObjectId(userId), // Ensure proper ObjectId
      address,
      paymentMethod: 'COD',
      paymentStatus: false, // More descriptive than just 'payment'
      status: 'pending', // Added order status
      createdAt: new Date(), // Better than Date.now() for MongoDB
      updatedAt: new Date()
    };

    // 3. Insert order
    const result = await orderCollection.insertOne(orderData);

    // 4. Clear user's cart
    await userCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { cartData: {} } }
    );

    return res.status(201).json({
      message: 'Order placed successfully',
      orderId: result.insertedId // Return the new order ID
    });

  } catch (error) {
    console.error("Order Placement Error:", error);
    
    // Handle specific errors
    if (error instanceof TypeError) {
      return res.status(400).json({ message: "Invalid data format" });
    }
    
    return res.status(500).json({ message: "Failed to place order" });
  }
});

// user order
app.get('/userOrders', isAuth, async (req, res) => {
  try {
    const userId = req.userId; 

    // 1. Find ALL orders for this user (not just one)
    const orders = await orderCollection.find({ 
      userId: new ObjectId(userId) 
    }).toArray();

    // 2. Handle case where no orders exist
    if (!orders || orders.length === 0) {
      return res.status(200).json({ 
        message: "No orders found",
        orders: [] 
      });
    }

    // 3. Return orders in reverse chronological order (newest first)
    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return res.status(200).json(orders);

  } catch (error) {
    console.error("User Orders Error:", error);
    
    // Handle invalid ObjectId format
    if (error instanceof TypeError) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    return res.status(500).json({ message: "Failed to fetch user orders" });
  }
});

// for admin (order)
app.get('/adminOrders',isAuthAdmin, async (req, res) => {
  try {
    // Convert cursor to array and sort by date (newest first)
    const orders = await orderCollection.find({})
      .sort({ createdAt: -1 }) // Sort by newest first
      .toArray();
    
    res.status(200).json(orders);

  } catch (error) {
    console.error("Admin Orders Error:", error);
    return res.status(500).json({ message: "Failed to fetch admin orders" });
  }
});

// update admin (order)
app.put('/adminOrders/:orderId', isAuthAdmin, async (req, res) => {
  try {
    const { orderId } = req.params; // Get from URL params
    const { status } = req.body;

    // Validate input
    if (!orderId || !status) {
      return res.status(400).json({ message: "Order ID and status are required" });
    }

    // Validate status values (optional but recommended)
    const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "Invalid status value" });
    }

    // Update the order
    const result = await orderCollection.updateOne(
      { _id: new ObjectId(orderId) }, // Correct filter
      { 
        $set: { 
          status,
          updatedAt: new Date() // Track when status was updated
        } 
      }
    );

    // Check if order was found and updated
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    return res.status(200).json({ 
      message: 'Status updated successfully',
      updated: true
    });

  } catch (error) {
    console.error("Update Order Error:", error);
    
    // Handle invalid ObjectId format
    if (error instanceof TypeError) {
      return res.status(400).json({ message: "Invalid order ID format" });
    }
    
    return res.status(500).json({ message: "Failed to update order status" });
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