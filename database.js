const express = require('express');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const multer = require('multer');

app = express();
const port = 3000;


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors()); 


app.use(session({
    secret: '12345',  
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', 
        maxAge: 24 * 60 * 60 * 1000  
    }
}));


app.use(express.static(path.join(__dirname, 'public')));


const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '12345',  
    database: 'signup'  
});


db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database: ', err);
        process.exit(1); 
    } else {
        console.log('Connected to the database');
    }
});




// Login route (GET)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route (POST)
app.post('/login', (req, res) => {
    const { emailinp, passinp } = req.body;

    if (!emailinp || !passinp) {
        return res.status(400).send('Please provide both email and password.');
    }

    db.query('SELECT * FROM users WHERE email = ?', [emailinp], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error querying database');
        }

        if (results.length === 0) {
            return res.status(400).send('No user found with that email');
        }

        const user = results[0];

        bcrypt.compare(passinp, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).send('Error comparing passwords');
            }

            if (isMatch) {
                req.session.user = { id: user.id, username: user.username, email: user.email };
                return res.redirect(`/homepage.html?id=${user.id}`);
            } else {
                return res.status(400).send('Invalid password');
            }
        });
    });
});

// Homepage route (GET)
app.get('/homepage.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// Serve signup page (GET)
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Sign up route (POST)
app.post('/signup', (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    
    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).send('Please fill out all fields');
    }

    
    if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
    }

    
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password: ', err);
            return res.status(500).send('Error processing your signup');
        }

        
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting into the database: ', err);
                return res.status(500).send('Error saving your account');
            }

            console.log('User signed up successfully');

            
            req.session.user = { id: result.insertId, username: username };

            
            res.redirect(`/homepage.html?id=${result.insertId}`);
        });
    });
});

// Logout route (GET)
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Check session route (GET)
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, username: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: './public/uploads/', 
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});
const upload = multer({ storage: storage });


// POST route to handle product submission
app.post('/sell', upload.single('product-image'), (req, res) => {
    console.log('Form Data:', req.body); 

    const { 'product-name': productName, condition, 'contact-info': contactInfo, price } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
    const userId = req.session.user ? req.session.user.id : null;

    
    if (!productName.trim() || !price || !contactInfo || !imagePath || !userId) {
        return res.status(400).send('Please provide all required fields (product name, price, contact info, image, and user).');
    }

    
    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
        return res.status(400).send('Please provide a valid price.');
    }

    
    const query = `
        INSERT INTO products (user_id, name, product_condition, image_path, contact_info, price)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(query, [userId, productName, condition, imagePath, contactInfo, parsedPrice], (err, result) => {
        if (err) {
            console.error('Error adding product:', err);
            return res.status(500).send('Error adding product.');
        }

        res.redirect(`/homepage.html?id=${userId}`);
    });
});



// Products route (GET)
app.get('/products', (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('User not logged in.');
    }

    const query = `SELECT * FROM products`;
    db.query(query, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching products.');
        }
        res.json(results);
    });
});


app.get('/user-info/:id', (req, res) => {
    const userId = req.session.user ? req.session.user.id : req.params.id;

    
    if (!userId) {
        return res.status(403).send('User not logged in.');
    }
    
    const query = 'SELECT username, email FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user info:', err);
            return res.status(500).send('Error fetching user info');
        }
        
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        console.log('Fetched user info:', results[0]);
        res.json(results[0]); 
    });
});

app.get('/user-products/:id', (req, res) => {
    const userId = req.params.id;

    
    if (!req.session.user) {
        return res.status(403).send('User  not logged in.');
    }

    const query = 'SELECT id, name, product_condition, price FROM products WHERE user_id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user products:', err);
            return res.status(500).send('Error fetching user products');
        }
        res.json({ products: results }); 
    });
});

app.get('/api/products/:id', (req, res) => {
    const productId = req.params.id;
    db.query('SELECT * FROM products WHERE id = ?', [productId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error fetching product' });
        if (results.length === 0) return res.status(404).json({ error: 'Product not found' });
        res.json(results[0]);
    });
});


// Update product details
app.put('/api/products/:id', upload.single('product-image'), (req, res) => {
    const { 'product-name': name, price, condition, 'contact-info': contactInfo } = req.body;
    const productId = req.params.id;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const updateQuery = `
        UPDATE products
        SET name = ?, price = ?, product_condition = ?, image_path = ?, contact_info = ?
        WHERE id = ?
    `;
    const updateValues = [name, price, condition, imagePath, contactInfo, productId];

    db.query(updateQuery, updateValues, (err, result) => {
        if (err) return res.status(500).json({ error: 'Error updating product' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Product not found or no changes made' });
        res.status(200).json({ message: 'Product updated successfully' });
    });
});

  
app.delete('/delete-product/:id', (req, res) => {
    const productId = req.params.id;
    
    
    const checkQuery = 'SELECT * FROM products WHERE id = ?';
    db.query(checkQuery, [productId], (err, results) => {
        if (err) {
            console.error('Error checking product:', err);
            return res.status(500).send('Error checking product');
        }
        
        if (results.length === 0) {
            return res.status(404).send('Product not found');
        }
        
        
        const deleteQuery = 'DELETE FROM products WHERE id = ?';
        db.query(deleteQuery, [productId], (err, results) => {
            if (err) {
                console.error('Error deleting product:', err);
                return res.status(500).send('Error deleting product');
            }
            
            res.status(200).send('Product deleted successfully');
        });
    });
});
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, username: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});


//profile update
app.put('/update-account/:id', (req, res) => {
    const userId = req.params.id;
    const { username, password } = req.body;

    
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Error hashing password' });
        }

        const query = 'UPDATE users SET username = ?, password = ? WHERE id = ?';
        db.query(query, [username, hashedPassword, userId], (err, result) => {
            if (err) {
                console.error('Error updating account:', err);
                return res.status(500).json({ error: 'Error updating account' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User  not found' });
            }
            res.status(200).json({ message: 'Account updated successfully' });
        });
    });
});

// DELETE route to delete a user account
app.delete('/delete-user/:userId', (req, res) => {
    const userId = req.params.userId;

    
    const deleteQuery = 'DELETE FROM users WHERE id = ?'; 

    db.execute(deleteQuery, [userId], (err, results) => {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).send('Error deleting user');
        }

        if (results.affectedRows === 0) {
            return res.status(404).send('User  not found');
        }

        res.status(200).send('User  account deleted successfully');
    });
});

// Fetch cart items for a user
app.get('/cart/:userId', (req, res) => {
    const userId = req.params.userId;

    const query = 'SELECT product_id, price, quantity FROM cart WHERE user_id = ?';
    db.execute(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching cart items:', err);
            return res.status(500).send('Error fetching cart items');
        }
        console.log('Fetched cart items:', results); 
        res.json(results); 
    });
});

// Add or update item in the cart
app.post('/add-to-cart', (req, res) => {
    const { userId, productId } = req.body;

    
    console.log('User  ID:', userId);
    console.log('Product ID:', productId);

    
    if (!userId || !productId) {
        return res.status(400).send('User  ID and Product ID are required');
    }

    
    const query = 'SELECT price FROM products WHERE id = ?';
    db.execute(query, [productId], (err, results) => {
        if (err) {
            console.error('Error fetching product price:', err);
            return res.status(500).send('Error fetching product price');
        }

        if (results.length === 0) {
            return res.status(404).send('Product not found');
        }

        const price = results[0].price;

        
        const checkQuery = 'SELECT quantity FROM cart WHERE user_id = ? AND product_id = ?';
        db.execute(checkQuery, [userId, productId], (err, results) => {
            if (err) {
                console.error('Error checking cart:', err);
                return res.status(500).send('Error checking cart');
            }

            if (results.length > 0) {
                
                const newQuantity = results[0].quantity + 1; 
                const updateQuery = 'UPDATE cart SET quantity = ?, price = ? WHERE user_id = ? AND product_id = ?';
                db.execute(updateQuery, [newQuantity, price, userId, productId], (err) => {
                    if (err) {
                        console.error('Error updating cart:', err);
                        return res.status(500).send('Error updating cart');
                    }
                    return res.status(200).send('Product quantity updated in cart');
                });
            } else {
                
                const insertQuery = 'INSERT INTO cart (user_id, product_id, price, quantity) VALUES (?, ?, ?, ?)';
                db.execute(insertQuery, [userId, productId, price, 1], (err) => { 
                    if (err) {
                        console.error('Error adding to cart:', err);
                        return res.status(500).send('Error adding to cart');
                    }
                    return res.status(200).send('Product added to cart');
                });
            }
        });
    });
});

app.post('/update-cart', (req, res) => {
    const { userId, productId, quantity } = req.body;

    
    if (!userId || !productId || quantity === undefined) {
        return res.status(400).send('User  ID, Product ID, and quantity are required');
    }

    
    if (quantity < 1) {
        return res.status(400).send('Quantity must be at least 1');
    }

    
    const updateQuery = 'UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?';
    db.execute(updateQuery, [quantity, userId, productId], (err) => {
        if (err) {
            console.error('Error updating cart quantity:', err);
            return res.status(500).send('Error updating cart quantity');
        }

        
        res.status(200).send('Cart quantity updated successfully');
    });
});

app.delete('/remove-from-cart/:productId', (req, res) => {
    const userId = req.session.userId; 
    const productId = req.params.productId;

    const query = 'DELETE FROM cart WHERE user_id = ? AND product_id = ?';
    
    db.execute(query, [userId, productId], (err, results) => {
        if (err) {
            console.error('Error removing item from cart:', err);
            return res.status(500).send('Error removing item from cart');
        }

        if (results.affectedRows === 0) {
            return res.status(404).send('Item not found in cart');
        }

        res.status(200).send('Item removed from cart successfully');
    });
});
app.post('/checkout/:userId', (req, res) => {
    const userId = req.params.userId;

    
    const query = 'SELECT SUM(price) AS total FROM cart WHERE user_id = ?';
    
    db.execute(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching total price:', err);
            return res.status(500).send('Error fetching total price');
        }

        const totalPrice = results[0].total;

        if (totalPrice === null) {
            return res.status(400).send('No items in cart to checkout');
        }

        
        const deleteQuery = 'DELETE FROM cart WHERE user_id = ?';
        
        db.execute(deleteQuery, [userId], (err) => {
            if (err) {
                console.error('Error clearing cart:', err);
                return res.status(500).send('Error clearing cart');
            }

            

            res.status(200).send(`Thank you for your purchase! Total amount: TK ${totalPrice}`);
        });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});






