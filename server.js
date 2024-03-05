const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const crypto = require('crypto');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const config = require('./config')

const blacklistedTokens = [];

// Middleware
app.use(bodyParser.json());

// Konfigurasi Database MySQL
const db = mysql.createConnection(config);

db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
    } else {
        console.log('Connected to MySQL');
    }
});


// Middleware to verify JWT token
function verifyToken(req, res, next) {
    // Get token from request headers
    const authHeader = req.header('Authorization');

    // Check if authHeader exists and has the correct format
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ success: false, message: 'Token is required' });
    }

    // Extract token from authHeader
    const token = authHeader.split(' ')[1];

    // Check if token is blacklisted
    if (blacklistedTokens.includes(authHeader)) {
        return res.status(401).json({ success: false, message: 'Token is blacklisted' });
    }

    // Verify token
    jwt.verify(token, 'caraba0', (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        req.user = decoded;
        next(); // Call next middleware
    });
}



app.get('/me', verifyToken, (req, res) => {
    const id_users = req.user.id_user;
    db.query('SELECT id,username,is_timer FROM users where id =' + id_users, (err, results) => {
        if (err) {
            console.error('Error querying rooms:', err);
            res.status(500).json({ success: false, message: 'Error querying rooms' });
        } else {
            res.json({ success: true, detail: results });
        }
    });
});


// 1. POST Login
app.post('/logins', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    // Verify the username and hashed password against the database
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.query(query, [username, hashedPassword], (err, results) => {
        if (err) {
            console.error('Error querying user:', err);
            res.status(500).json({ success: false, message: 'Error querying user' });
        } else if (results.length > 0) {
            const userId = results[0].id; // Assuming your user table has an 'id' field
            const isTimer = results[0].is_timer; // Assuming your user table has an 'id' field

            // User authenticated, generate a JWT token with user ID in the payload
            const token = jwt.sign({ id_user: userId, username: username }, 'caraba0'); // Replace 'your-secret-key' with a secure secret key

            res.json({ success: true, message: 'Login berhasil', token: token, timer: isTimer });

        } else {
            res.status(401).json({ success: false, message: 'Login gagal' });
        }
    });
});


app.post('/logout', (req, res) => {
    // Invalidate the token on the server side by adding it to the blacklist
    const token = req.headers['authorization'];
    blacklistedTokens.push(token);

    // Clear token on client side
    res.clearCookie('token'); // Clear token cookie if using cookies
    res.status(200).json({ success: true, message: 'Logout berhasil' });
});



// 2. GET Data Meja
app.get('/rooms', verifyToken, (req, res) => {
    db.query('SELECT * FROM rooms join panels on panels.id = rooms.id_panels', (err, results) => {
        if (err) {
            console.error('Error querying rooms:', err);
            res.status(500).json({ success: false, message: 'Error querying rooms' });
        } else {
            res.json({ success: true, rooms: results });
        }
    });
});

// 3. POST Config with Key
app.post('/configs', verifyToken, (req, res) => {
    const { ip, secret } = req.body;
    const configIdToUpdate = 1; // Assuming you want to update the record where id is 1

    // Check if the record with id = configIdToUpdate exists
    const checkQuery = 'SELECT * FROM configs WHERE id = ?';

    db.query(checkQuery, [configIdToUpdate], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Error checking configuration:', checkErr);
            res.status(500).json({ success: false, message: 'Error checking configuration' });
            return;
        }

        if (checkResults.length > 0) {
            // The record exists, update it
            const updateQuery = 'UPDATE configs SET ip = ?  WHERE id = ?';

            db.query(updateQuery, [ip, configIdToUpdate], (updateErr, updateResults) => {
                if (updateErr) {
                    console.error('Error updating configuration:', updateErr);
                    res.status(500).json({ success: false, message: 'Error updating configuration' });
                } else {
                    res.json({ success: true, message: 'Konfigurasi diperbarui' });
                }
            });
        } else {
            // The record does not exist, insert it
            const insertQuery = 'INSERT INTO configs (id, ip,secret) VALUES (?, ?,?)';

            db.query(insertQuery, [configIdToUpdate, ip, secret], (insertErr, insertResults) => {
                if (insertErr) {
                    console.error('Error inserting configuration:', insertErr);
                    res.status(500).json({ success: false, message: 'Error inserting configuration' });
                } else {
                    res.json({ success: true, message: 'Konfigurasi ditambahkan' });
                }
            });
        }
    });
});



// 3. GET Config with Key
app.get('/configs', verifyToken, (req, res) => {
    db.query('SELECT * FROM configs', (err, results) => {
        if (err) {
            console.error('Error querying rooms:', err);
            res.status(500).json({ success: false, message: 'Error querying rooms' });
        } else {
            res.json({ success: true, rooms: results });
        }
    });
});


app.post('/orders-open-billing', verifyToken, (req, res) => {
    const { id_rooms, duration, name } = req.body;
    const type = "OPEN-BILLING";
    const status = "START";
    const id_users = req.user.id_user;
    // // Check if id_rooms exists in the rooms table
    const checkRoomsQuery = 'SELECT * FROM rooms WHERE id = ?';
    db.query(checkRoomsQuery, [id_rooms], (roomsErr, roomsResults) => {
        if (roomsErr) {
            console.error('Error checking rooms:', roomsErr);
            res.status(500).json({ success: false, message: 'Error checking rooms' });
            return;
        }

        if (roomsResults.length === 0) {
            res.status(400).json({ success: false, message: 'Invalid id_rooms' });
            return;
        }

        // Check if id_users exists in the users table
        const checkUsersQuery = 'SELECT * FROM users WHERE id = ?';
        db.query(checkUsersQuery, [id_users], (usersErr, usersResults) => {
            if (usersErr) {
                console.error('Error checking users:', usersErr);
                res.status(500).json({ success: false, message: 'Error checking users' });
                return;
            }

            if (usersResults.length === 0) {
                res.status(400).json({ success: false, message: 'Invalid id_users' });
                return;
            }
            if (name.length === 0) {
                res.status(400).json({ success: false, message: 'Pastikan nama terisi' });
                return;
            }

            // Check if the room status is not already set to 1
            if (roomsResults[0].status === 1) {
                res.status(400).json({ success: false, message: 'Room is already booked' });
                return;
            }

            // Calculate start_time and end_time based on current time and duration
            const currentTime = new Date();
            const startTime = currentTime;
            const endTime = new Date(currentTime.getTime() + duration * 60 * 60 * 1000); // Adding provided duration in hours

            // If both id_rooms and id_users are valid, insert the order
            const insertOrderQuery = 'INSERT INTO orders (id_rooms, id_users, start_time, end_time, status, type,name) VALUES (?, ?, ?, ?, ? , ?,?)';
            db.query(insertOrderQuery, [id_rooms, id_users, startTime, endTime, status, type, name], (insertErr, insertResults) => {
                if (insertErr) {
                    console.error('Error inserting order:', insertErr);
                    res.status(500).json({ success: false, message: 'Error inserting order' });
                } else {
                    // Update status in rooms table to 1
                    const updateStatusQuery = 'UPDATE rooms SET status = 1 WHERE id = ?';
                    db.query(updateStatusQuery, [id_rooms], (updateStatusErr, updateStatusResults) => {
                        if (updateStatusErr) {
                            console.error('Error updating status in rooms:', updateStatusErr);
                            res.status(500).json({ success: false, message: 'Error updating status in rooms' });
                        } else {
                            res.json({ success: true, message: 'Pesanan disimpan, status diperbarui' });
                        }
                    });
                }
            });
        });
    });
});

app.post('/orders-open-table', verifyToken, (req, res) => {
    const { id_rooms, name } = req.body;
    const type = "OPEN-TABLE";
    const status = "START";
    const id_users = req.user.id_user;
    // Check if id_rooms exists in the rooms table
    const checkRoomsQuery = 'SELECT * FROM rooms WHERE id = ?';
    db.query(checkRoomsQuery, [id_rooms], (roomsErr, roomsResults) => {
        if (roomsErr) {
            console.error('Error checking rooms:', roomsErr);
            res.status(500).json({ success: false, message: 'Error checking rooms' });
            return;
        }

        if (roomsResults.length === 0) {
            res.status(400).json({ success: false, message: 'Invalid id_rooms' });
            return;
        }

        // Check if id_users exists in the users table
        const checkUsersQuery = 'SELECT * FROM users WHERE id = ?';
        db.query(checkUsersQuery, [id_users], (usersErr, usersResults) => {
            if (usersErr) {
                console.error('Error checking users:', usersErr);
                res.status(500).json({ success: false, message: 'Error checking users' });
                return;
            }

            if (usersResults.length === 0) {
                res.status(400).json({ success: false, message: 'Invalid id_users' });
                return;
            }

            if (name.length === 0) {
                res.status(400).json({ success: false, message: 'Pastikan nama terisi' });
                return;
            }

            // Check if the room status is not already set to 1
            if (roomsResults[0].status === 1) {
                res.status(400).json({ success: false, message: 'Room is already booked' });
                return;
            }

            // Calculate start_time and end_time based on current time and duration
            const currentTime = new Date();
            const startTime = currentTime;

            // If both id_rooms and id_users are valid, insert the order
            const insertOrderQuery = 'INSERT INTO orders (id_rooms, id_users, start_time, status, type,name) VALUES (?, ?, ?, ?,  ?,?)';
            db.query(insertOrderQuery, [id_rooms, id_users, startTime, status, type, name], (insertErr, insertResults) => {
                if (insertErr) {
                    console.error('Error inserting order:', insertErr);
                    res.status(500).json({ success: false, message: 'Error inserting order' });
                } else {
                    // Update status in rooms table to 1
                    const updateStatusQuery = 'UPDATE rooms SET status = 1 WHERE id = ?';
                    db.query(updateStatusQuery, [id_rooms], (updateStatusErr, updateStatusResults) => {
                        if (updateStatusErr) {
                            console.error('Error updating status in rooms:', updateStatusErr);
                            res.status(500).json({ success: false, message: 'Error updating status in rooms' });
                        } else {
                            res.json({ success: true, message: 'Pesanan disimpan, status diperbarui' });
                        }
                    });
                }
            });
        });
    });
});


app.post('/orders-stop-open-table', verifyToken, (req, res) => {
    const { order_id } = req.body;

    // Check if order exists
    const checkOrderQuery = 'SELECT * FROM orders WHERE id = ?';
    db.query(checkOrderQuery, [order_id], (orderErr, orderResults) => {
        if (orderErr) {
            console.error('Error checking order:', orderErr);
            res.status(500).json({ success: false, message: 'Error checking order' });
            return;
        }

        if (orderResults.length === 0) {
            res.status(400).json({ success: false, message: 'Invalid order_id' });
            return;
        }

        const currentTime = new Date();
        const end_time = currentTime;

        const roomId = orderResults[0].id_rooms;

        // Update order status to 'STOP'
        const updateOrderQuery = 'UPDATE orders SET status = ? ,end_time = ? WHERE id = ?';
        db.query(updateOrderQuery, ['STOP', end_time, order_id], (updateOrderErr, updateOrderResults) => {
            if (updateOrderErr) {
                console.error('Error updating order status:', updateOrderErr);
                res.status(500).json({ success: false, message: 'Error updating order status' });
                return;
            }

            // Update room status to 0
            const updateRoomStatusQuery = 'UPDATE rooms SET status = 0 WHERE id = ?';
            db.query(updateRoomStatusQuery, [roomId], (updateRoomStatusErr, updateRoomStatusResults) => {
                if (updateRoomStatusErr) {
                    console.error('Error updating room status:', updateRoomStatusErr);
                    res.status(500).json({ success: false, message: 'Error updating room status' });
                    return;
                }

                res.json({ success: true, message: 'Order stopped, room status updated' });
            });
        });
    });
});

// 4. POST Stop Order
app.post('/orders-stop-open-billing', verifyToken, (req, res) => {
    const { order_id } = req.body;

    // Check if order exists
    const checkOrderQuery = 'SELECT * FROM orders WHERE id = ?';
    db.query(checkOrderQuery, [order_id], (orderErr, orderResults) => {
        if (orderErr) {
            console.error('Error checking order:', orderErr);
            res.status(500).json({ success: false, message: 'Error checking order' });
            return;
        }

        if (orderResults.length === 0) {
            res.status(400).json({ success: false, message: 'Invalid order_id' });
            return;
        }

        const roomId = orderResults[0].id_rooms;

        // Update order status to 'STOP'
        const updateOrderQuery = 'UPDATE orders SET status = ? WHERE id = ?';
        db.query(updateOrderQuery, ['STOP', order_id], (updateOrderErr, updateOrderResults) => {
            if (updateOrderErr) {
                console.error('Error updating order status:', updateOrderErr);
                res.status(500).json({ success: false, message: 'Error updating order status' });
                return;
            }

            // Update room status to 0
            const updateRoomStatusQuery = 'UPDATE rooms SET status = 0 WHERE id = ?';
            db.query(updateRoomStatusQuery, [roomId], (updateRoomStatusErr, updateRoomStatusResults) => {
                if (updateRoomStatusErr) {
                    console.error('Error updating room status:', updateRoomStatusErr);
                    res.status(500).json({ success: false, message: 'Error updating room status' });
                    return;
                }

                res.json({ success: true, message: 'Order stopped, room status updated' });
            });
        });
    });
});

// 6. GET Newest Orders for Each Room
app.get('/newest-orders', verifyToken, (req, res) => {
    const query = `
    SELECT
	rooms.id AS room_id,
	rooms.code,
	rooms.name,
	rooms.status status_rooms,
	orders.status status_order,
	orders.type,
    panels.ip,
    panels.secret,
    COALESCE ( MAX( orders.id ), 0 ) AS id, 
    COALESCE ( MAX( orders.start_time ), 'No orders' ) AS newest_order_start_time,
	COALESCE ( MAX( orders.end_time ), 'No orders' ) AS newest_order_end_time 
FROM
	rooms
    join panels on panels.id = rooms.id_panels
	LEFT JOIN orders ON rooms.id = orders.id_rooms 
    where rooms.rooms_available  = 1
GROUP BY
	rooms.id,
	rooms.name
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error querying newest orders:', err);
            res.status(500).json({ success: false, message: 'Error querying newest orders' });
        } else {
            res.json({ success: true, newestOrders: results });
        }
    });
});



app.get('/newest-bg-orders', verifyToken, (req, res) => {
    const query = `
    SELECT
	rooms.id AS room_id,
	rooms.code,
	rooms.name,
	rooms.status status_rooms,
	orders.status status_order,
	orders.type,
    panels.ip,
    panels.secret,
    COALESCE ( MAX( orders.id ), 0 ) AS id, 
    COALESCE ( MAX( orders.start_time ), 'No orders' ) AS newest_order_start_time,
	COALESCE ( MAX( orders.end_time ), 'No orders' ) AS newest_order_end_time 
FROM
	rooms
    join panels on panels.id = rooms.id_panels
	LEFT JOIN orders ON rooms.id = orders.id_rooms 
WHERE 
orders.type = "OPEN-BILLING" and
orders.status = "START"
GROUP BY
	rooms.id,
	rooms.name
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error querying newest orders:', err);
            res.status(500).json({ success: false, message: 'Error querying newest orders' });
        } else {
            res.json({ success: true, newestOrders: results });
        }
    });
});



app.post('/history-orders', verifyToken, (req, res) => {
    const ordersName = req.body.search; // Assuming the parameter is sent in the request body
    const startDate = req.body.startDate; // Filter by start date
    const endDate = req.body.endDate; // Filter by end date
    const page = req.body.page || 1; // Default to page 1 if not provided
    const pageSize = req.body.pageSize || 10; // Default page size to 10 if not provided
    const startIndex = (page - 1) * pageSize; // Calculate the start index for pagination

    // Construct the SQL query with date filters and pagination
    let query = `
    SELECT
        rooms.name,
        orders.status status_order,
        orders.type,
        orders.name AS orders_name,
        orders.id AS id, 
        orders.start_time,
        orders.end_time,
        users.username cashier_name 
    FROM
        rooms
        JOIN orders ON rooms.id = orders.id_rooms
        JOIN users ON users.id = orders.id_users
    WHERE
        orders.name LIKE ? 
        AND end_time IS NOT NULL`;

    const queryParams = [`%${ordersName}%`]; // Parameters for the SQL query

    // Add date filters if provided
    if (startDate) {
        query += ' AND DATE(orders.start_time) >= ?';
        queryParams.push(startDate);
    }
    if (endDate) {
        query += ' AND DATE(orders.start_time) <= ?';
        queryParams.push(endDate);
    }

    // Add pagination
    query += ' LIMIT ?, ?';
    queryParams.push(startIndex, pageSize);

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error querying history orders:', err);
            res.status(500).json({ success: false, message: 'Error querying orders' });
        } else {
            res.json({ success: true, total: results.length, matchedOrders: results });
        }
    });
});


app.post('/orders-stop-open-bg-billing', (req, res) => {
    const { order_id, key } = req.body;

    if (key != "51383db2eb3e126e52695488e0650f68ea43b4c6") {
        res.status(500).json({ success: false, message: 'Error Key Saslah' });
        return;
    }

    // Check if order exists
    const checkOrderQuery = 'SELECT * FROM orders WHERE id = ?';
    db.query(checkOrderQuery, [order_id], (orderErr, orderResults) => {
        if (orderErr) {
            console.error('Error checking order:', orderErr);
            res.status(500).json({ success: false, message: 'Error checking order' });
            return;
        }

        if (orderResults.length === 0) {
            res.status(400).json({ success: false, message: 'Invalid order_id' });
            return;
        }

        const roomId = orderResults[0].id_rooms;

        // Update order status to 'STOP'
        const updateOrderQuery = 'UPDATE orders SET status = ? WHERE id = ?';
        db.query(updateOrderQuery, ['STOP', order_id], (updateOrderErr, updateOrderResults) => {
            if (updateOrderErr) {
                console.error('Error updating order status:', updateOrderErr);
                res.status(500).json({ success: false, message: 'Error updating order status' });
                return;
            }

            // Update room status to 0
            const updateRoomStatusQuery = 'UPDATE rooms SET status = 0 WHERE id = ?';
            db.query(updateRoomStatusQuery, [roomId], (updateRoomStatusErr, updateRoomStatusResults) => {
                if (updateRoomStatusErr) {
                    console.error('Error updating room status:', updateRoomStatusErr);
                    res.status(500).json({ success: false, message: 'Error updating room status' });
                    return;
                }

                res.json({ success: true, message: 'Order stopped, room status updated' });
            });
        });
    });
});

// Jalankan server
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});
