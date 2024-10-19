const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const { extractTTPs } = require('./ttpExtractor');
const app = express();

app.use(bodyParser.json());

app.post('/process', async (req, res) => {
    const content = req.body.content;
    console.log('Received content:', content); // Debug statement
    try {
        const processedContent = await extractTTPs(content);
        res.json({ processedContent });
    } catch (error) {
        console.error('Error:', error); // Debug statement
        res.status(500).send('Error processing the file.');
    }
});

// Serve the static files
app.use(express.static(path.join(__dirname)));

// Handle the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const port = 4000;
app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
});
