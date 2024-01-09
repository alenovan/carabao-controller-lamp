const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const crypto = require('crypto');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const config = require('./config')
// Middleware
app.use(bodyParser.json());

// Konfigurasi Database MySQL
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
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the Authorization header

    if (!token) return res.status(403).json({ success: false, message: 'Access denied' });

    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) return res.status(401).json({ success: false, message: 'Invalid token' });

        req.user = decoded;
        next();
    });
}

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
            // User authenticated, generate a JWT token
            const token = jwt.sign({ username: username }, 'your-secret-key'); // Replace 'your-secret-key' with a secure secret key
            res.json({ success: true, message: 'Login berhasil', token: token });
        } else {
            res.status(401).json({ success: false, message: 'Login gagal' });
        }
    });
});

// 2. GET Data Meja
app.get('/rooms', verifyToken, (req, res) => {
    db.query('SELECT * FROM rooms', (err, results) => {
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
            const updateQuery = 'UPDATE configs SET ip = ? , secret = ? WHERE id = ?';

            db.query(updateQuery, [ip, secret, configIdToUpdate], (updateErr, updateResults) => {
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


app.post('/orders', verifyToken, (req, res) => {
    const { id_rooms, id_users, start_time, end_time, status } = req.body;

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

            // Check if the room status is not already set to 1
            if (roomsResults[0].status === 1) {
                res.status(400).json({ success: false, message: 'Room is already booked' });
                return;
            }

            // If both id_rooms and id_users are valid, insert the order
            const insertOrderQuery = 'INSERT INTO orders (id_rooms, id_users, start_time, end_time, status) VALUES (?, ?, ?, ?, ?)';
            db.query(insertOrderQuery, [id_rooms, id_users, start_time, end_time, status], (insertErr, insertResults) => {
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

// 4. POST Stop Order
app.post('/stop-order', verifyToken, (req, res) => {
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
	COALESCE ( MAX( orders.end_time ), 'No orders' ) AS newest_order_end_time 
FROM
	rooms
	LEFT JOIN orders ON rooms.id = orders.id_rooms 
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


// Jalankan server
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});
