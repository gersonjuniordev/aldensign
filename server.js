const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { PDFDocument, rgb } = require('pdf-lib');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');
const app = express();
const port = 3000;

// PostgreSQL configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://aldensign_owner:npg_gvJAy6Ykudr0@ep-plain-recipe-ac92z21j-pooler.sa-east-1.aws.neon.tech/aldensign?sslmode=require',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initializeDatabase() {
    try {
        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                cpf VARCHAR(14) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create documents table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS documents (
                id VARCHAR(32) PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                filename VARCHAR(255) NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                signed_at TIMESTAMP,
                signed_filename VARCHAR(255),
                log_filename VARCHAR(255),
                signature_fields JSONB
            )
        `);

        // Create signatures table with string types for position values
        await pool.query(`
            CREATE TABLE IF NOT EXISTS signatures (
                id SERIAL PRIMARY KEY,
                document_id VARCHAR(32) REFERENCES documents(id),
                page INTEGER NOT NULL,
                left_position VARCHAR(20) NOT NULL,
                top_position VARCHAR(20) NOT NULL,
                width VARCHAR(20) NOT NULL,
                height VARCHAR(20) NOT NULL,
                signature_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
    }
}

// Initialize database on startup
initializeDatabase();

// Configure session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Store users and documents
const users = new Map();
const documents = new Map();

// Generate a unique document ID
function generateDocumentId() {
    return crypto.randomBytes(8).toString('hex');
}

// Convert base64 to PNG buffer
function base64ToPNG(base64String) {
    const base64Data = base64String.replace(/^data:image\/png;base64,/, '');
    return Buffer.from(base64Data, 'base64');
}

// Serve static files
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/signed', express.static('signed'));
app.use('/logs', express.static('logs'));

// Ensure required directories exist
const requiredDirs = ['uploads', 'signed', 'logs'];
requiredDirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login.html');
    }
}

// Register endpoint
app.post('/api/auth/register', express.json(), async (req, res) => {
    const { name, email, password, cpf } = req.body;

    try {
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR cpf = $2',
            [email, cpf]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const result = await pool.query(
            'INSERT INTO users (name, email, password, cpf) VALUES ($1, $2, $3, $4) RETURNING id',
            [name, email, hashedPassword, cpf]
        );

        res.json({ success: true, userId: result.rows[0].id });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});

// Login endpoint
app.post('/api/auth/login', express.json(), async (req, res) => {
    const { email, password } = req.body;

    try {
        // Get user from database
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session
        req.session.userId = user.id;
        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check authentication status
app.get('/api/auth/status', (req, res) => {
    res.json({ isAuthenticated: !!req.session.userId });
});

// Get user info endpoint
app.get('/api/auth/user', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, email, cpf FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error getting user info:', error);
        res.status(500).json({ error: 'Error getting user info' });
    }
});

// Upload document (protected)
app.post('/api/upload', isAuthenticated, upload.single('document'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
        // Get user information
        const userResult = await pool.query(
            'SELECT id FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userId = userResult.rows[0].id;

        // Generate document ID
        const documentId = crypto.randomBytes(16).toString('hex');

        // Save document to database
        await pool.query(
            'INSERT INTO documents (id, user_id, filename, original_name) VALUES ($1, $2, $3, $4)',
            [documentId, userId, req.file.filename, req.file.originalname]
        );

        res.json({
            documentId,
            filename: req.file.originalname,
            fileUrl: `/uploads/${req.file.filename}`
        });
    } catch (error) {
        console.error('Error uploading document:', error);
        res.status(500).json({ error: 'Error uploading document' });
    }
});

// Save signature fields (protected)
app.post('/api/documents/:documentId/signatures', isAuthenticated, express.json(), async (req, res) => {
    const { documentId } = req.params;
    const { signatureFields } = req.body;

    if (!documentId) {
        return res.status(400).json({ error: 'Document ID is required' });
    }

    try {
        // Verify document exists and belongs to user
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND user_id = $2',
            [documentId, req.session.userId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        // Update document with signature fields
        await pool.query(
            'UPDATE documents SET signature_fields = $1 WHERE id = $2',
            [JSON.stringify(signatureFields), documentId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Error saving signatures:', error);
        res.status(500).json({ error: 'Error saving signatures' });
    }
});

// Get document info (protected)
app.get('/api/documents/:documentId', isAuthenticated, async (req, res) => {
    const { documentId } = req.params;
    
    try {
        // Get document from database
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1',
            [documentId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const document = documentResult.rows[0];
        
        // Check if file exists
        const filePath = path.join(__dirname, 'uploads', document.filename);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Document file not found' });
        }

        // Parse signature fields if they exist
        let signatureFields = [];
        if (document.signature_fields) {
            try {
                // If it's already an object, use it directly
                if (typeof document.signature_fields === 'object') {
                    signatureFields = document.signature_fields;
                } else {
                    // Otherwise try to parse it as JSON
                    signatureFields = JSON.parse(document.signature_fields);
                }
            } catch (error) {
                console.error('Error parsing signature fields:', error);
                signatureFields = [];
            }
        }

        res.json({
            id: document.id,
            filename: document.filename,
            originalName: document.original_name,
            status: document.status,
            signatureFields: signatureFields,
            signedAt: document.signed_at,
            downloadUrl: document.signed_filename ? `/signed/${document.signed_filename}` : null,
            logUrl: document.log_filename ? `/logs/${document.log_filename}` : null
        });
    } catch (error) {
        console.error('Error getting document:', error);
        res.status(500).json({ error: 'Error getting document' });
    }
});

// Generate signing link (protected)
app.post('/api/documents/:documentId/generate-link', isAuthenticated, async (req, res) => {
    const { documentId } = req.params;

    try {
        // Verify document exists and belongs to user
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND user_id = $2',
            [documentId, req.session.userId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        // Generate a secure signing link
        const signingLink = `http://localhost:3000/sign/${documentId}`;
        res.json({ signingLink });
    } catch (error) {
        console.error('Error generating signing link:', error);
        res.status(500).json({ error: 'Error generating signing link' });
    }
});

// Delete document (protected)
app.delete('/api/documents/:documentId', isAuthenticated, async (req, res) => {
    const { documentId } = req.params;
    
    try {
        // Verify document exists and belongs to user
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND user_id = $2',
            [documentId, req.session.userId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const document = documentResult.rows[0];

        // Delete signatures first (due to foreign key constraint)
        await pool.query('DELETE FROM signatures WHERE document_id = $1', [documentId]);

        // Delete document
        await pool.query('DELETE FROM documents WHERE id = $1', [documentId]);

        // Delete files
        const filesToDelete = [
            path.join(__dirname, 'uploads', document.filename),
            path.join(__dirname, 'signed', document.signed_filename),
            path.join(__dirname, 'logs', document.log_filename)
        ];

        for (const file of filesToDelete) {
            if (file && fs.existsSync(file)) {
                fs.unlinkSync(file);
            }
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({ error: 'Error deleting document' });
    }
});

// Enhanced logging function
async function generateSigningLog(documentId, signatures, user, ip, req) {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([595, 842]); // A4 size
    
    const { width, height } = page.getSize();
    
    // Add title
    page.drawText('Document Signing Log', {
        x: 50,
        y: height - 50,
        size: 20,
        color: rgb(0, 0, 0),
    });
    
    // Add document information
    const documentInfo = [
        `Document ID: ${documentId}`,
        `Signing Date: ${new Date().toISOString()}`,
        `IP Address: ${ip}`,
        `User Agent: ${req.headers['user-agent']}`,
        `User: ${user.name} (${user.email})`,
        `User CPF: ${user.cpf}`,
        '',
        'Signature Details:'
    ];
    
    let y = height - 100;
    documentInfo.forEach(line => {
        page.drawText(line, {
            x: 50,
            y,
            size: 12,
            color: rgb(0, 0, 0),
        });
        y -= 20;
    });
    
    // Add signature details
    signatures.forEach((signature, index) => {
        const signatureInfo = [
            `Signature ${index + 1}:`,
            `- Page: ${signature.page}`,
            `- Position: ${signature.left}, ${signature.top}`,
            `- Dimensions: ${signature.width} x ${signature.height}`,
            `- Timestamp: ${new Date().toISOString()}`,
            `- Browser: ${req.headers['user-agent']}`,
            `- IP Address: ${ip}`,
            ''
        ];
        
        signatureInfo.forEach(line => {
            page.drawText(line, {
                x: 50,
                y,
                size: 10,
                color: rgb(0, 0, 0),
            });
            y -= 15;
        });
    });
    
    // Add footer
    page.drawText('This document serves as a legal record of the electronic signatures applied to the document.', {
        x: 50,
        y: 50,
        size: 10,
        color: rgb(0, 0, 0),
    });
    
    // Save the log PDF
    const logBytes = await pdfDoc.save();
    const logFilename = `signing_log_${documentId}.pdf`;
    const logPath = path.join(__dirname, 'logs', logFilename);
    
    // Create logs directory if it doesn't exist
    if (!fs.existsSync(path.join(__dirname, 'logs'))) {
        fs.mkdirSync(path.join(__dirname, 'logs'));
    }
    
    fs.writeFileSync(logPath, logBytes);
    return logFilename;
}

// Submit signatures (public)
app.post('/api/documents/:documentId/submit', express.json(), async (req, res) => {
    try {
        const { documentId } = req.params;
        const { signatures } = req.body;
        const ip = req.ip;
        
        // Get document information
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1',
            [documentId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const document = documentResult.rows[0];

        // Generate signing log
        const logFilename = await generateSigningLog(documentId, signatures, {
            name: 'Signer',
            email: 'signer@example.com',
            cpf: '000.000.000-00'
        }, ip, req);

        // Read the PDF
        const pdfBytes = fs.readFileSync(path.join('uploads', document.filename));
        const pdfDoc = await PDFDocument.load(pdfBytes);
        const pages = pdfDoc.getPages();

        // Add signatures to PDF
        for (const field of signatures) {
            const page = pages[field.page - 1];
            if (page && field.signature) {
                try {
                    const signatureBuffer = base64ToPNG(field.signature);
                    const signatureImage = await pdfDoc.embedPng(signatureBuffer);
                    
                    const { width: pageWidth, height: pageHeight } = page.getSize();
                    const fieldLeft = parseInt(field.left.replace('px', ''));
                    const fieldTop = parseInt(field.top.replace('px', ''));
                    const fieldWidth = parseInt(field.width.replace('px', ''));
                    const fieldHeight = parseInt(field.height.replace('px', ''));
                    
                    const scale = 1.5;
                    const x = fieldLeft / scale;
                    const y = pageHeight - (fieldTop / scale) - (fieldHeight / scale);
                    const width = fieldWidth / scale;
                    const height = fieldHeight / scale;
                    
                    page.drawImage(signatureImage, {
                        x,
                        y,
                        width,
                        height,
                    });
                } catch (error) {
                    console.error('Error processing signature:', error);
                }
            }
        }

        // Create signed directory if it doesn't exist
        const signedDir = 'signed';
        if (!fs.existsSync(signedDir)) {
            fs.mkdirSync(signedDir);
        }

        // Save the signed PDF
        const signedPdfBytes = await pdfDoc.save();
        const signedFilename = `signed_${document.filename}`;
        fs.writeFileSync(path.join(signedDir, signedFilename), signedPdfBytes);

        // Update document status in database
        await pool.query(
            'UPDATE documents SET status = $1, signed_at = $2, signed_filename = $3, log_filename = $4 WHERE id = $5',
            ['signed', new Date(), signedFilename, logFilename, documentId]
        );

        // Save signatures to database with string position values
        for (const signature of signatures) {
            await pool.query(
                'INSERT INTO signatures (document_id, page, left_position, top_position, width, height, signature_data) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                [
                    documentId, 
                    signature.page, 
                    signature.left, 
                    signature.top, 
                    signature.width, 
                    signature.height, 
                    signature.signature
                ]
            );
        }

        res.json({ 
            success: true,
            downloadUrl: `/signed/${signedFilename}`,
            logUrl: `/logs/${logFilename}`
        });
    } catch (error) {
        console.error('Error signing document:', error);
        res.status(500).json({ error: 'Error signing document: ' + error.message });
    }
});

// Get list of documents (protected)
app.get('/api/documents', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, original_name, status, signed_at, signed_filename, log_filename FROM documents WHERE user_id = $1 ORDER BY created_at DESC',
            [req.session.userId]
        );

        const documents = result.rows.map(doc => ({
            id: doc.id,
            originalName: doc.original_name,
            status: doc.status,
            signedAt: doc.signed_at,
            downloadUrl: doc.signed_filename ? `/signed/${doc.signed_filename}` : null,
            logUrl: doc.log_filename ? `/logs/${doc.log_filename}` : null
        }));

        res.json(documents);
    } catch (error) {
        console.error('Error fetching documents:', error);
        res.status(500).json({ error: 'Error fetching documents' });
    }
});

// Serve signing page (public)
app.get('/sign/:documentId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sign.html'));
});

// Check if document exists (public)
app.get('/api/documents/:documentId/check', async (req, res) => {
    const { documentId } = req.params;
    
    try {
        const documentResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1',
            [documentId]
        );

        if (documentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const document = documentResult.rows[0];
        
        // Check if file exists
        const filePath = path.join(__dirname, 'uploads', document.filename);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Document file not found' });
        }

        // Parse signature fields if they exist
        let signatureFields = [];
        if (document.signature_fields) {
            try {
                if (typeof document.signature_fields === 'object') {
                    signatureFields = document.signature_fields;
                } else {
                    signatureFields = JSON.parse(document.signature_fields);
                }
            } catch (error) {
                console.error('Error parsing signature fields:', error);
                signatureFields = [];
            }
        }

        res.json({
            id: document.id,
            filename: document.filename,
            originalName: document.original_name,
            status: document.status,
            signatureFields: signatureFields,
            signedAt: document.signed_at,
            downloadUrl: document.signed_filename ? `/signed/${document.signed_filename}` : null,
            logUrl: document.log_filename ? `/logs/${document.log_filename}` : null
        });
    } catch (error) {
        console.error('Error getting document:', error);
        res.status(500).json({ error: 'Error getting document' });
    }
});

// Redirect root to login if not authenticated
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 