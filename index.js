const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid'); 
const path = require('path');
const cors = require('cors');

const dbPath = path.join(__dirname, "data.db");

const app = express();
app.use(express.json());
app.use(cors());

let db = null;

const initializingServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });
        app.listen(3000, () => {
            console.log("Server started at http://localhost:3000");
        });
    } catch (e) {
        console.log(`Error: ${e.message}`);
        process.exit(1);
    }
};

initializingServer();

app.post('/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const existingUser = await db.get('SELECT * FROM users WHERE email = ?', [email]);

        if (existingUser) {
            return res.status(400).json({ success: false, message: 'User already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        const userId = uuidv4(); 
        await db.run('INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)', 
            [userId, name, email, hashedPassword]);

        return res.json({ success: true, message: 'User created successfully.' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});


app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(404).json({ success:false, message: 'User not found.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success:false, message: 'Password is wrong.' });
        }

        const token = jwt.sign({email:email,id:user.id }, 'todos'); 

        return res.status(200).json({ success:true,token });
    } catch (error) {
        console.error(error);
        return res.status(500).json({success:false, message: 'Server error.' });
    }
});


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    jwt.verify(token, 'todos', (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token.' });
        }
        req.user = user;
        console.log(req.user)
        next(); 
    });
};

app.post('/api/tasks', authenticateToken, async (req, res) => {
    const { title, description } = req.body;
    try {
        const taskId = uuidv4();
        await db.run('INSERT INTO tasks (id, title, description, completed,user_email) VALUES (?, ?, ?, ?,?)', 
            [taskId, title, description, false,req.user.email]);

        return res.status(201).json({ success: true, message: 'Task created successfully.', taskId });
    } catch (error) {
        console.error('Error creating task:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
    const {email} = req.user
    try {
        const tasks = await db.all('SELECT * FROM tasks WHERE user_email = ?',[email]);        
        return res.status(200).json({ tasks });
    } catch (error) {
        console.error('Error fetching tasks:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }``
});


app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, completed } = req.body;

    try {
        await db.run('UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?', 
            [title, description, completed, id]);

        return res.status(200).json({ success: true, message: 'Task updated successfully.' });
    } catch (error) {
        console.error('Error updating task:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        await db.run('DELETE FROM tasks WHERE id = ?', [id]);
        return res.status(200).json({ success: true, message: 'Task deleted successfully.' });
    } catch (error) {
        console.error('Error deleting task:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/profile', authenticateToken, async (req, res) => {
    const userId = req.user.id; 

    try {
        const user = await db.get('SELECT id, name, email FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        return res.status(200).json({ success: true, user });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});


app.put('/profile/update', authenticateToken, async (req, res) => {
    const { name, email, password } = req.body;

    try {
        let updateQuery = 'UPDATE users SET name = ?, email = ?';
        const params = [name, email];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', password = ?';
            params.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        params.push(req.user.id);

        await db.run(updateQuery, params);
        return res.status(200).json({ success: true, message: 'Profile updated successfully.' });
    } catch (error) {
        console.error('Error updating profile:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});
