const express = require("express")
const bcrypt = require("bcryptjs")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const { PrismaClient } = require("@prisma/client")
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const axios = require('axios')
const cheerio = require("cheerio")
const puppeteer = require("puppeteer")
const http = require('https')
const { ApifyClient } = require('apify-client')

const prisma = new PrismaClient()
const app = express()

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key"

// Initialize the ApifyClient with your API token
const client = new ApifyClient({
    token: process.env.APIFY_API_TOKEN, // Ensure this is set in your .env file
})

app.use(express.json())
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  }),
)

// File upload middleware
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Use absolute path
    const uploadDir = path.join(__dirname, 'uploads');
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage })

// Serve static files
const uploadPath = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploadPath));

app.post("/api/auth/signup", async (req, res) => {
  console.log('Received signup request:', req.body); // Debug log
  const { email, password, username } = req.body

  if (!email || !password || !username) {
    return res.status(400).json({ message: "All fields are required" })
  }

  try {
    // Check if user already exists
    const existingUser = await prisma.admin.findFirst({
      where: {
        OR: [
          { email },
          { username }
        ]
      }
    })

    if (existingUser) {
      return res.status(400).json({ 
        message: existingUser.email === email 
          ? "Email already exists" 
          : "Username already exists" 
      })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create new user
    const newUser = await prisma.admin.create({
      data: {
        email,
        username,
        password: hashedPassword,
      }
    })

    console.log('User created successfully:', newUser.id); // Debug log
    res.status(201).json({ message: "User created successfully" })
  } catch (error) {
    console.error("Signup error:", error)
    res.status(500).json({ message: "Error creating user", error: error.message })
  }
})

app.post("/api/auth/signin", async (req, res) => {
  console.log('Received signin request:', req.body); // Debug log
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" })
  }

  try {
    const admin = await prisma.admin.findUnique({ where: { email } })
    console.log('Found user:', admin ? 'yes' : 'no'); // Debug log

    if (!admin) {
      return res.status(400).json({ message: "User not found" })
    }

    const isPasswordValid = await bcrypt.compare(password, admin.password)
    console.log('Password valid:', isPasswordValid); // Debug log

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" })
    }

    // Create JWT token
    const token = jwt.sign(
      {
        id: admin.id,
        email: admin.email,
        username: admin.username,
        role: admin.role,
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    )

    res.json({
      token,
      user: {
        id: admin.id,
        email: admin.email,
        username: admin.username,
        firstName: admin.firstName,
        lastName: admin.lastName,
        avatar: admin.avatar,
        role: admin.role,
      }
    })
  } catch (error) {
    console.error("Signin error:", error)
    res.status(500).json({ message: "Error during signin", error: error.message })
  }
})

// Protected route example
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  console.log("ME endpoint called");
  console.log("User from token:", req.user);
  try {
    const admin = await prisma.admin.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        avatar: true,
        role: true,
      }
    });
    console.log("Found admin:", admin);
    res.json(admin);
  } catch (error) {
    console.error("Error in /me endpoint:", error);
    res.status(500).json({ message: "Error fetching user data" });
  }
})

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ message: "No token provided" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" })
    }
    req.user = user
    next()
  })
}

// Upload avatar endpoint
app.post("/api/upload-avatar", authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    console.log("Upload request from:", req.user); // Debug log
    console.log("File details:", req.file); // Debug log

    // Generate the full URL for the uploaded file
    const avatarUrl = `${process.env.API_URL}/uploads/${req.file.filename}`;
    console.log("Generated avatar URL:", avatarUrl); // Debug log

    // Update avatar based on user role
    if (req.user.role === "admin") {
      const updatedAdmin = await prisma.admin.update({
        where: { id: req.user.id },
        data: { avatar: avatarUrl }
      });
      console.log("Updated admin:", updatedAdmin); // Debug log
    } else if (req.user.role === "client") {
      const updatedClient = await prisma.client.update({
        where: { id: req.user.id },
        data: { avatar: avatarUrl }
      });
      console.log("Updated client:", updatedClient); // Debug log
    } else {
      throw new Error(`Invalid user role: ${req.user.role}`);
    }

    res.json({ avatarUrl });
  } catch (error) {
    console.error("Detailed error uploading avatar:", {
      error: error.message,
      stack: error.stack,
      user: req.user
    });
    res.status(500).json({ 
      message: "Error uploading avatar",
      details: error.message 
    });
  }
});

// Update profile endpoint
app.put("/api/auth/update-profile", authenticateToken, async (req, res) => {
  try {
    const { username, email, firstName, lastName, avatar } = req.body;

    // Check if username or email is already taken
    if (username || email) {
      const existingUser = await prisma.admin.findFirst({
        where: {
          OR: [
            { username: username || undefined },
            { email: email || undefined }
          ],
          NOT: { id: req.user.id }
        }
      });

      if (existingUser) {
        return res.status(400).json({
          message: existingUser.email === email
            ? "Email already exists"
            : "Username already exists"
        });
      }
    }

    // Update user profile
    const updatedUser = await prisma.admin.update({
      where: { id: req.user.id },
      data: {
        username: username || undefined,
        email: email || undefined,
        firstName: firstName || undefined,
        lastName: lastName || undefined,
        avatar: avatar || undefined,
      }
    });

    res.json({
      message: "Profile updated successfully",
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        avatar: updatedUser.avatar,
        role: updatedUser.role,
      }
    });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

// Admin signup endpoint
app.post("/api/auth/admin/signup", async (req, res) => {
  const { email, password, username, adminCode } = req.body;

  // Verify admin code
  if (adminCode !== process.env.ADMIN_SIGNUP_CODE) {
    return res.status(403).json({ message: "Invalid admin code" });
  }

  try {
    // Check if admin already exists
    const existingAdmin = await prisma.admin.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    });

    if (existingAdmin) {
      return res.status(400).json({
        message: existingAdmin.email === email ? "Email already exists" : "Username already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new admin
    await prisma.admin.create({
      data: {
        email,
        username,
        password: hashedPassword,
        role: "admin", // Ensure role is set to admin
      },
    });

    res.status(201).json({ message: "Admin account created successfully" });
  } catch (error) {
    console.error("Admin signup error:", error);
    res.status(500).json({ message: "Error creating admin account" });
  }
});

// Admin signin endpoint
app.post("/api/auth/admin/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await prisma.admin.findUnique({ 
      where: { email },
      select: {
        id: true,
        email: true,
        username: true,
        password: true,
        role: true,
        firstName: true,
        lastName: true,
        avatar: true,
      }
    });

    if (!admin || admin.role !== "admin") {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    const { password: _, ...adminData } = admin;
    res.json({ token, user: adminData });
  } catch (error) {
    console.error("Admin signin error:", error);
    res.status(500).json({ message: "Error signing in" });
  }
});

// Client signup endpoint
app.post("/api/auth/client/signup", async (req, res) => {
  const { email, password, username, companyName } = req.body;

  if (!email || !password || !username || !companyName) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Check if client already exists
    const existingClient = await prisma.client.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    });

    if (existingClient) {
      return res.status(400).json({
        message: existingClient.email === email ? "Email already exists" : "Username already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new client
    await prisma.client.create({
      data: {
        email,
        username,
        password: hashedPassword,
        companyName,
        role: "client",
      },
    });

    res.status(201).json({ message: "Client account created successfully" });
  } catch (error) {
    console.error("Client signup error:", error);
    res.status(500).json({ message: "Error creating client account" });
  }
});

// Client signin endpoint
app.post("/api/auth/client/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const client = await prisma.client.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        username: true,
        password: true,
        companyName: true,
        role: true,
        firstName: true,
        lastName: true,
        avatar: true,
        bio: true,
        phone: true,
      },
    });

    if (!client || client.role !== "client") {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, client.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: client.id, role: client.role }, JWT_SECRET, { expiresIn: "24h" });

    const { password: _, ...clientData } = client;
    res.json({ token, user: clientData });
  } catch (error) {
    console.error("Client signin error:", error);
    res.status(500).json({ message: "Error signing in" });
  }
});

// Update client profile endpoint
app.put("/api/auth/client/update-profile", authenticateToken, async (req, res) => {
  if (req.user.role !== "client") {
    return res.status(403).json({ message: "Unauthorized. Client access only." });
  }

  try {
    const { username, email, firstName, lastName, avatar, bio, phone } = req.body;

    // Check if username or email is already taken
    if (username || email) {
      const existingClient = await prisma.client.findFirst({
        where: {
          OR: [
            { username: username || undefined },
            { email: email || undefined },
          ],
          NOT: { id: req.user.id },
        },
      });

      if (existingClient) {
        return res.status(400).json({
          message: existingClient.email === email ? "Email already exists" : "Username already exists",
        });
      }
    }

    // Update client profile
    const updatedClient = await prisma.client.update({
      where: { id: req.user.id },
      data: {
        username: username || undefined,
        email: email || undefined,
        firstName: firstName || undefined,
        lastName: lastName || undefined,
        avatar: avatar || undefined,
        bio: bio || undefined,
        phone: phone || undefined,
      },
    });

    const { password: _, ...clientData } = updatedClient;
    res.json({
      message: "Profile updated successfully",
      user: clientData,
    });
  } catch (error) {
    console.error("Error updating client profile:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

// New endpoint for scraping LinkedIn ads
app.get('/scrape', async (req, res) => {
    const browser = await puppeteer.launch({ headless: true }); // Run in headless mode
    const page = await browser.newPage();

    // Navigate to LinkedIn Ad Library
    await page.goto('https://www.linkedin.com/ad-library/home');

    // Wait for the search form to load
    await page.waitForSelector('#search-form');

    // Input search criteria
    const companyName = req.query.company || 'Your Company Name'; // Get company name from query parameter
    await page.type('input[name="accountOwner"]', companyName);
    
    // Click the search button
    await page.click('#search-form-submit');

    // Wait for results to load
    await page.waitForSelector('.base-ad-preview-card', { timeout: 10000 }); // Wait for ad cards to load

    // Scrape the results
    const ads = await page.evaluate(() => {
        const adElements = document.querySelectorAll('.base-ad-preview-card'); // Adjust selector based on actual structure
        console.log(`Found ${adElements.length} ad elements`); // Log the number of ad elements found
        return Array.from(adElements).map(ad => ({
            advertiser: ad.querySelector('div.flex.flex-col.self-center > div > div')?.innerText, // Advertiser name
            description: ad.querySelector('.sponsored-content-headline h2')?.innerText, // Ad description
            link: ad.querySelector('a[data-tracking-control-name="ad_library_ad_preview_video_thumbnail_image"]')?.href, // Link to ad details
            commentaryComment: ad.querySelector('.commentary__container ')?.innerText,
            logo: ad.querySelector('img[alt="advertiser logo"]')?.src, // Logo image
            postImage: ad.querySelector('.ad-preview__dynamic-dimensions-image')?.src // Post image
        }));
    });

    // Log the scraped ads
    console.log(ads);

    // Send the scraped ads as a response
    res.json(ads);

    await browser.close();
});

// New endpoint to save an ad
app.post("/api/save-ad", authenticateToken, async (req, res) => {
  const { advertiser, commentaryComment, description, link, logo, postImage } = req.body

  console.log("Incoming ad data:", req.body) // Log the incoming data

  try {
    const newAd = await prisma.ad.create({
      data: {
        advertiser,
        description,
        commentaryComment,
        link,
        logo,
        postImage,
        admin: {
          connect: { id: req.user.id }, // Connect the ad to the authenticated admin
        },
      },
    })
    res.status(201).json(newAd)
  } catch (error) {
    console.error("Error saving ad:", error) // Log the error
    res.status(500).json({ message: "Error saving ad", error: error.message })
  }
})

// New endpoint to get saved ads
app.get("/api/saved-ads", async (req, res) => {
    try {
        const savedAds = await prisma.ad.findMany(); // Fetch all saved ads
        res.status(200).json(savedAds);
    } catch (error) {
        console.error("Error fetching saved ads:", error);
        res.status(500).json({ message: "Error fetching saved ads", error: error.message });
    }
});

// New endpoint to get all clients
// app.get("/api/clients", authenticateToken, async (req, res) => {
app.get("/api/clients", async (req, res) => {
    try {
        const clients = await prisma.client.findMany(); // Fetch all clients
        res.status(200).json(clients);
    } catch (error) {
        console.error("Error fetching clients:", error);
        res.status(500).json({ message: "Error fetching clients", error: error.message });
    }
});

// Post an ad
app.post("/api/post-ad", authenticateToken, async (req, res) => {
  const { id, tags } = req.body

  try {
    const updatedAd = await prisma.ad.update({
      where: { id },
      data: { 
        isPosted: true,
        tags: tags || []
      },
    })

    res.status(200).json({ message: "Ad posted successfully", ad: updatedAd })
  } catch (error) {
    console.error("Error posting ad:", error)
    res.status(500).json({ message: "Error posting ad", error: error.message })
  }
})

// Get posted ads
app.get("/api/posted-ads", authenticateToken, async (req, res) => {
  try {
    const postedAds = await prisma.ad.findMany({
      where: {
        isPosted: true,
      },
    })
    res.status(200).json(postedAds)
  } catch (error) {
    console.error("Error fetching posted ads:", error)
    res.status(500).json({ message: "Error fetching posted ads", error: error.message })
  }
})

// New endpoint to get all posted ads for admin
app.get("/api/admin/posted-ads", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Unauthorized. Admin access only." });
  }

  try {
    const postedAds = await prisma.ad.findMany({
      where: {
        isPosted: true,
      },
    });
    res.status(200).json(postedAds);
  } catch (error) {
    console.error("Error fetching posted ads:", error);
    res.status(500).json({ message: "Error fetching posted ads", error: error.message });
  }
});

app.delete("/api/delete-ad/:id", authenticateToken, async (req, res) => {
  const { id } = req.params

  try {
    const deletedAd = await prisma.ad.delete({
      where: { id },
    })

    if (!deletedAd) {
      return res.status(404).json({ message: "Ad not found" })
    }

    res.status(200).json({ message: "Ad deleted successfully", ad: deletedAd })
  } catch (error) {
    console.error("Error deleting ad:", error)
    res.status(500).json({ message: "Error deleting ad", error: error.message })
  }
})

// Create a new collection
app.post("/api/collections", authenticateToken, async (req, res) => {
  if (req.user.role !== "client") {
    return res.status(403).json({ message: "Unauthorized. Client access only." })
  }

  const { name, description } = req.body

  try {
    const newCollection = await prisma.collection.create({
      data: {
        name,
        description,
        client: { connect: { id: req.user.id } },
      },
    })

    res.status(201).json(newCollection)
  } catch (error) {
    console.error("Error creating collection:", error)
    res.status(500).json({ message: "Error creating collection", error: error.message })
  }
})

// Get all collections for a client
app.get("/api/collections", authenticateToken, async (req, res) => {
  if (req.user.role !== "client") {
    return res.status(403).json({ message: "Unauthorized. Client access only." })
  }

  try {
    const collections = await prisma.collection.findMany({
      where: { clientId: req.user.id },
      include: { _count: { select: { ads: true } } },
    })

    res.status(200).json(collections)
  } catch (error) {
    console.error("Error fetching collections:", error)
    res.status(500).json({ message: "Error fetching collections", error: error.message })
  }
})

// Save ad to collection
app.post("/api/save-to-collection", authenticateToken, async (req, res) => {
  if (req.user.role !== "client") {
    return res.status(403).json({ message: "Unauthorized. Client access only." });
  }

  const { adId, collectionId } = req.body;

  if (!adId || !collectionId) {
    return res.status(400).json({ message: "Both adId and collectionId are required." });
  }

  try {
    const savedAd = await prisma.adCollection.create({
      data: {
        ad: { connect: { id: adId } },
        collection: { connect: { id: collectionId } },
      },
    });

    res.status(200).json({ message: "Ad saved to collection successfully", savedAd });
  } catch (error) {
    console.error("Error saving ad to collection:", error);
    res.status(500).json({ message: "Error saving ad to collection", error: error.message });
  }
});

// Get ads for a specific collection
app.get("/api/collections/:collectionId/ads", authenticateToken, async (req, res) => {
  if (req.user.role !== "client") {
    return res.status(403).json({ message: "Unauthorized. Client access only." })
  }

  const { collectionId } = req.params

  try {
    const ads = await prisma.ad.findMany({
      where: {
        collections: {
          some: {
            collection: {
              id: collectionId,
              clientId: req.user.id,
            },
          },
        },
      },
    })

    res.status(200).json(ads)
  } catch (error) {
    console.error("Error fetching ads for collection:", error)
    res.status(500).json({ message: "Error fetching ads for collection", error: error.message })
  }
})


const PORT = process.env.PORT || 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))