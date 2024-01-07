const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { UNAUTHORIZED, FORBIDDEN, OK } = require('http-status-codes');
const cors = require('cors');

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());
const jwtSecretKey = 'defaultSecretKey';
const refreshSecretKey = 'refreshSecretKey';

const generateRefreshToken = (userId, username) => {
    return jwt.sign({ user: { id: userId, username } }, refreshSecretKey, { expiresIn: '7d' });
};

app.post('/api/register', async (req, res) => {
    try {
        const { name, username, email, password } = req.body;

        if (!name || !username || !password || !email) {
            return res.status(400).json({ error: 'All fields (name, username, password, email) are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { username },
                    { email },
                ],
            },
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already taken' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await prisma.user.create({
            data: {
                name,
                username,
                email,
                password: hashedPassword,
            },
        });

        res.json({ message: 'User registered successfully', user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during registration' });
    }
});

// Endpoint for user login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await prisma.user.findUnique({
            where: { username },
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ user: { id: user.id, username: user.username } }, jwtSecretKey, { expiresIn: '1h' });
        const refreshToken = generateRefreshToken(user.id, user.username);

        res.json({ message: 'Login successful', token, refreshToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

app.post('/api/refresh-token', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token is required' });
        }

        const decoded = jwt.verify(refreshToken, refreshSecretKey);

        const newAccessToken = jwt.sign({ user: { id: decoded.user.id, username: decoded.user.username } }, jwtSecretKey, { expiresIn: '1h' });

        res.json({ message: 'Token refreshed successfully', token: newAccessToken });
    } catch (error) {
        console.error(error);
        if (error.name === 'TokenExpiredError') {
            return res.status(UNAUTHORIZED).json({ message: 'Refresh token has expired.' });
        }
        return res.status(FORBIDDEN).json({ message: 'Invalid refresh token.' });
    }
});

const verifyToken = (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(UNAUTHORIZED).json({ message: 'Access denied. Token not provided or in the correct format.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, jwtSecretKey);
        req.userId = decoded.user.id;
        req.username = decoded.user.username;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(UNAUTHORIZED).json({ message: 'Token has expired.' });
        }
        return res.status(FORBIDDEN).json({ message: 'Invalid token.' });
    }
};

module.exports = verifyToken;

// Endpoint for creating a post (requires token verification)
app.post('/api/create-post', verifyToken, async (req, res) => {
    try {
        const { project_name, sub_project, schedule_target, status, description } = req.body;
        const userId = req.userId;
        const createdBy = req.username;

        if (!project_name || !sub_project || !schedule_target || !status || !description) {
            return res.status(400).json({ error: 'All fields (project_name, sub_project, schedule_target, status, description) are required' });
        }

        const post = await prisma.post.create({
            data: {
                project_name,
                sub_project,
                schedule_target,
                status,
                description,
                userId,
                createdBy,
            },
        });

        res.json({ message: 'Post created successfully', post });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during post creation' });
    }
});

// Endpoint for getting a post by ID
app.get('/api/get-post/:postId', async (req, res) => {
    try {
        const postId = parseInt(req.params.postId);

        const post = await prisma.post.findUnique({
            where: { id: postId },
        });

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.json({ message: 'Post retrieved successfully', post });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during post retrieval' });
    }
});


// Endpoint for editing a post (requires token verification)
app.put('/api/edit-post/:postId', verifyToken, async (req, res) => {
    try {
        const postId = parseInt(req.params.postId);
        const { project_name, sub_project, schedule_target, status, description } = req.body;
        const userId = req.userId;

        if (!project_name || !sub_project || !schedule_target || !status || !description) {
            return res.status(400).json({ error: 'All fields (project_name, sub_project, schedule_target, status, description) are required' });
        }

        const existingPost = await prisma.post.findUnique({
            where: { id: postId },
        });

        if (!existingPost || existingPost.userId !== userId) {
            return res.status(404).json({ error: 'Post not found or unauthorized to edit' });
        }

        const updatedPost = await prisma.post.update({
            where: { id: postId },
            data: {
                project_name,
                sub_project,
                schedule_target,
                status,
                description,
            },
        });

        res.json({ message: 'Post updated successfully', post: updatedPost });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during post update' });
    }
});

// Endpoint for deleting a post (requires token verification)
app.delete('/api/delete-post/:postId', verifyToken, async (req, res) => {
    try {
        const postId = parseInt(req.params.postId);
        const userId = req.userId;

        const existingPost = await prisma.post.findUnique({
            where: { id: postId },
        });

        if (!existingPost || existingPost.userId !== userId) {
            return res.status(404).json({ error: 'Post not found or unauthorized to delete' });
        }

        await prisma.post.delete({
            where: { id: postId },
        });

        res.json({ message: 'Post deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during post deletion' });
    }
});

// Endpoint for getting posts by username
app.get('/api/get-posts-by-username/:username', async (req, res) => {
    try {
        const username = req.params.username;

        const user = await prisma.user.findUnique({
            where: { username },
            include: {
                posts: true, // This assumes a relationship between User and Post models in Prisma
            },
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Posts retrieved successfully', posts: user.posts });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error during post retrieval' });
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
