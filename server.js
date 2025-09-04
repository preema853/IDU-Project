const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');

const app = express();
const port = 3000;
const SECRET_KEY = 'your_jwt_secret_key';

// --- NODEMAILER CONFIGURATION ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: 'your_email@gmail.com', //⬅️ Replace this with your email
        pass: 'your_app_password'     // ⬅️ Replace this with your 16-digit App Password
    }
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Rate Limiting Middleware
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

app.use('/login', authLimiter);
app.use('/register', authLimiter);
app.use('/forgot-password', authLimiter);
app.use('/reset-password', authLimiter);


// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// MySQL Connection Pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'internship_management',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Middleware to check authentication
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

// Middleware to authorize user roles
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).send('Access Denied');
        }
        next();
    };
};

// --- ROUTES ---

// Render login page
app.get('/login', (req, res) => {
    res.render('login', { error: null, success: req.query.success });
});

// Render registration page
app.get('/register', async (req, res) => {
    try {
        const [departments] = await pool.execute('SELECT id, name FROM departments');
        res.render('register', { error: null, departments });
    } catch (err) {
        console.error('Failed to fetch departments for registration:', err);
        res.render('register', { error: 'Could not load page data.', departments: [] });
    }
});

// User registration
app.post('/register', async (req, res) => {
    const { username, password, email, role, name, department_id, reg_number } = req.body;
    if (!username || !password || !role || !email) {
        const [departments] = await pool.execute('SELECT id, name FROM departments');
        return res.render('register', { error: 'Please fill out all required fields.', departments });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, email]
        );

        const userId = result.insertId;

        if (role === 'student') {
            if (!name || !department_id || !reg_number) {
                const [departments] = await pool.execute('SELECT id, name FROM departments');
                return res.render('register', { error: 'Full name, registration number, and department are required for students.', departments });
            }
            await pool.execute(
                'INSERT INTO students (user_id, name, department_id, reg_number) VALUES (?, ?, ?, ?)',
                [userId, name, department_id, reg_number]
            );
        }
        res.redirect('/login?success=Registration successful. Please log in.');
    } catch (err) {
        console.error('Registration error:', err);
        const [departments] = await pool.execute('SELECT id, name FROM departments');
        let errorMessage = 'Username or email already exists.';
        if (err.code === 'ER_DUP_ENTRY' && err.sqlMessage.includes('reg_number')) {
            errorMessage = 'Registration number already exists.';
        }
        res.render('register', { error: errorMessage, departments });
    }
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: 'Invalid username or password.', success: null });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });

        if (user.role === 'student') {
            res.redirect('/student/dashboard');
        } else {
            res.redirect('/report/dashboard');
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('An error occurred during login.');
    }
});

// --- PASSWORD RESET ROUTES ---

// Render forgot password page
app.get('/forgot-password', (req, res) => {
    res.render('forgot_password', { error: null, success: null });
});

// Handle forgot password request
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    const genericSuccessMessage = 'If an account with that email exists, a password reset link has been sent.';

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) {
            return res.render('forgot_password', { error: null, success: genericSuccessMessage });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 3600000);

        await pool.execute(
            'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
            [token, expires, user.id]
        );

        const resetLink = `http://localhost:${port}/reset-password/${token}`;

        await transporter.sendMail({
            from: '"Internship Portal" <your_email@gmail.com>',
            to: user.email,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click the link below to reset your password:</p>
                        <a href="${resetLink}">${resetLink}</a>
                        <p>This link will expire in one hour. If you did not request this, please ignore this email.</p>`
        });

        res.render('forgot_password', {
            error: null,
            success: genericSuccessMessage
        });

    } catch (err) {
        console.error('Forgot password error:', err);
        res.render('forgot_password', {
            error: 'Failed to send reset email. Check your server logs.',
            success: null
        });
    }
});

// Render reset password page
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
            [token]
        );

        if (!rows[0]) {
            return res.render('login', { error: 'Password reset link is invalid or has expired.', success: null });
        }

        res.render('reset_password', { token, error: null });
    } catch (err) {
        console.error('Reset password GET error:', err);
        res.status(500).send('An error occurred.');
    }
});

// Handle reset password submission
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
            [token]
        );

        const user = rows[0];
        if (!user) {
            return res.render('login', { error: 'Password reset link is invalid or has expired.', success: null });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
            [hashedPassword, user.id]
        );

        await transporter.sendMail({
            from: '"Internship Portal" <your_email@gmail.com>',
            to: user.email,
            subject: '✅ Your Password Has Been Changed',
            html: `<p>This is a confirmation that the password for your account has just been changed.</p>
                        <p>If you did not make this change, please contact support immediately.</p>`
        });

        res.redirect('/login?success=Password has been successfully reset. You can now log in.');
    } catch (err) {
        console.error('Reset password POST error:', err);
        res.render('reset_password', {
            token,
            error: 'An error occurred. Please try again.'
        });
    }
});


// Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// Student Dashboard
app.get('/student/dashboard', authenticateToken, authorizeRole(['student']), async (req, res) => {
    try {
        const [studentRows] = await pool.execute('SELECT id, name FROM students WHERE user_id = ?', [req.user.id]);
        const studentId = studentRows[0].id;
        const studentName = studentRows[0].name;

        // CORRECTED: Select document ID and file path for view/delete links
        const [documentRows] = await pool.execute('SELECT id, document_type, file_path FROM documents WHERE student_id = ?', [studentId]);

        const requiredDocs = ['internship_letter', 'proforma', 'monthly_report', 'final_report', 'certificate'];
        const submissionStatus = requiredDocs.map(docType => {
            // Find the document from the fetched rows
            const found = documentRows.find(d => d.document_type === docType);
            return {
                id: found ? found.id : null, // Pass the document ID
                name: docType.replace(/_/g, ' ').toUpperCase(),
                status: found ? 'Submitted' : 'Pending',
                canUpload: !found,
                type: docType,
                file: found ? found.file_path : null // Pass the file path
            };
        });

        res.render('student_dashboard', { studentName, submissionStatus });
    } catch (err) {
        console.error('Student dashboard error:', err);
        res.status(500).send('An error occurred.');
    }
});

// Student document upload
app.post('/student/upload', authenticateToken, authorizeRole(['student']), upload.single('document'), async (req, res) => {
    const { documentType } = req.body;

    if (!documentType || !req.file) {
        return res.status(400).send('Document type and file are required.');
    }
    const filename = req.file.filename;

    try {
        const [studentRows] = await pool.execute('SELECT id FROM students WHERE user_id = ?', [req.user.id]);
        const studentId = studentRows[0].id;

        const [existingDoc] = await pool.execute(
            'SELECT * FROM documents WHERE student_id = ? AND document_type = ?',
            [studentId, documentType]
        );

        if (existingDoc.length > 0) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting duplicate file:', err);
            });
            return res.status(409).send('This document type has already been submitted.');
        }

        await pool.execute(
            'INSERT INTO documents (student_id, document_type, file_path) VALUES (?, ?, ?)',
            [studentId, documentType, filename]
        );
        res.redirect('/student/dashboard');
    } catch (err) {
        console.error('File upload error:', err);
        res.status(500).send('An error occurred during file upload.');
    }
});

// Student view document
app.get('/student/view/:id', authenticateToken, authorizeRole(['student']), async (req, res) => {
    const docId = req.params.id;
    try {
        const [rows] = await pool.execute(
            'SELECT file_path FROM documents d JOIN students s ON d.student_id = s.id WHERE d.id = ? AND s.user_id = ?',
            [docId, req.user.id]
        );

        if (!rows[0]) return res.status(404).send('File not found');

        const filePath = path.join(uploadDir, rows[0].file_path);
        if (!fs.existsSync(filePath)) return res.status(404).send('File missing on server');

        res.sendFile(filePath, { headers: { 'Content-Disposition': 'inline' } });
    } catch (err) {
        console.error('View error:', err);
        res.status(500).send('An error occurred.');
    }
});

// Student delete document
app.post('/student/delete/:id', authenticateToken, authorizeRole(['student']), async (req, res) => {
    const docId = req.params.id;
    try {
        const [rows] = await pool.execute(
            'SELECT file_path FROM documents d JOIN students s ON d.student_id = s.id WHERE d.id = ? AND s.user_id = ?',
            [docId, req.user.id]
        );

        if (!rows[0]) return res.status(404).send('File not found');

        const filePath = path.join(uploadDir, rows[0].file_path);

        // Delete from DB
        await pool.execute('DELETE FROM documents WHERE id = ?', [docId]);

        // Delete from filesystem
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        res.redirect('/student/dashboard');
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).send('An error occurred.');
    }
});

// Common function to get student reports
async function getStudentReports(departmentId) {
    const requiredDocs = ['internship_letter', 'proforma', 'monthly_report', 'final_report', 'certificate'];

    let sqlQuery = `
        SELECT s.id as studentId, s.name as studentName, s.reg_number, d.name as departmentName
        FROM students s
        JOIN departments d ON s.department_id = d.id
    `;
    let queryParams = [];

    if (departmentId && departmentId !== 'all') {
        sqlQuery += ' WHERE s.department_id = ?';
        queryParams.push(departmentId);
    }

    const [students] = await pool.execute(sqlQuery, queryParams);

    for (const student of students) {
        const [submittedDocs] = await pool.execute(
            'SELECT document_type, file_path FROM documents WHERE student_id = ?',
            [student.studentId]
        );

        const submittedDocsMap = submittedDocs.reduce((acc, doc) => {
            acc[doc.document_type] = doc.file_path;
            return acc;
        }, {});

        student.submissionStatus = {};
        student.submittedDocs = [];
        student.pendingDocs = [];

        requiredDocs.forEach(docType => {
            if (submittedDocsMap[docType]) {
                student.submissionStatus[docType] = { status: 'Submitted', filename: submittedDocsMap[docType] };
                student.submittedDocs.push(docType);
            } else {
                student.submissionStatus[docType] = { status: 'Pending', filename: null };
                student.pendingDocs.push(docType);
            }
        });
    }

    const [deptRows] = await pool.execute('SELECT id, name FROM departments');
    return { students, departments: deptRows, requiredDocs };
}


// Route to generate PDF report
app.get('/report/generate-pdf', authenticateToken, authorizeRole(['dean', 'admin', 'sig']), async (req, res) => {
    const departmentId = req.query.departmentId || 'all';
    const isFilteredByAllDepartments = departmentId === 'all';

    try {
        const { students, requiredDocs } = await getStudentReports(departmentId);

        const doc = new PDFDocument();
        const filename = `Internship_Report_${departmentId}.pdf`;
        res.setHeader('Content-disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-type', 'application/pdf');

        doc.pipe(res);

        doc.fontSize(24).font('Helvetica-Bold').text('Internship Submission Report', { align: 'center' }).moveDown(1.5);
        doc.font('Helvetica');

        // Filter students into two groups
        const submittedStudents = students.filter(student =>
            requiredDocs.every(docType => student.submissionStatus[docType].status === 'Submitted')
        );
        const pendingStudents = students.filter(student =>
            requiredDocs.some(docType => student.submissionStatus[docType].status === 'Pending')
        );

        // Section for students who submitted all documents
        doc.fontSize(16).fillColor('green').text('Students Who Have Submitted All Documents', { underline: true }).moveDown(0.5);
        doc.fillColor('black');
        if (submittedStudents.length > 0) {
            submittedStudents.forEach((student, index) => {
                let text = `${index + 1}. ${student.studentName} (Reg No: ${student.reg_number})`;
                if (isFilteredByAllDepartments) {
                    text += `, Dept: ${student.departmentName}`;
                }
                doc.fontSize(12).text(text);
            });
        } else {
            doc.fontSize(12).text('No students have submitted all required documents yet.').moveDown();
        }

        doc.moveDown(2);

        // Section for students with pending documents
        doc.fontSize(16).fillColor('red').text('Students with Pending Documents', { underline: true }).moveDown(0.5);
        doc.fillColor('black');
        if (pendingStudents.length > 0) {
            pendingStudents.forEach((student, index) => {
                doc.fontSize(12).font('Helvetica-Bold').text(`${index + 1}. ${student.studentName}`).font('Helvetica');
                doc.fontSize(10).text(`   • Registration Number: ${student.reg_number}`);
                if (isFilteredByAllDepartments) {
                    doc.text(`   • Department: ${student.departmentName}`);
                }

                // Show submitted documents if any exist
                if (student.submittedDocs.length > 0) {
                    doc.text(`   • Submitted Documents: ${student.submittedDocs.map(d => d.replace(/_/g, ' ')).join(', ')}`);
                }
                
                // Show pending documents
                if (student.pendingDocs.length > 0) {
                    doc.text(`   • Pending Documents: ${student.pendingDocs.map(d => d.replace(/_/g, ' ')).join(', ')}`);
                }
                doc.moveDown(0.5);
            });
        } else {
            doc.fontSize(12).text('All students have submitted all required documents.').moveDown();
        }

        doc.end();

    } catch (err) {
        console.error('PDF generation error:', err);
        res.status(500).send('An error occurred while generating the report.');
    }
});


// Report Dashboard
app.get('/report/dashboard', authenticateToken, authorizeRole(['dean', 'admin', 'sig']), async (req, res) => {
    try {
        const departmentId = req.query.departmentId || 'all';
        const { students, departments, requiredDocs } = await getStudentReports(departmentId);
        res.render('report_dashboard', { departments, students, requiredDocs, selectedDeptId: departmentId });
    } catch (err) {
        console.error('Report dashboard error:', err);
        res.status(500).send('An error occurred.');
    }
});

// Route to render the document viewer page
app.get('/view/:filename', authenticateToken, (req, res) => {
    const { filename } = req.params;
    res.render('view_document', { filename });
});

// Endpoint to serve uploaded files
app.get('/uploads/:filename', authenticateToken, (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(uploadDir, filename);

    if (path.dirname(filePath) === uploadDir && fs.existsSync(filePath)) {
        res.sendFile(filePath, { headers: { 'Content-Disposition': 'inline' } });
    } else {
        res.status(404).send('File not found.');
    }
});

// Root path redirects to login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});