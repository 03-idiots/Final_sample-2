document.getElementById('uploadForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = async function(e) {
            const content = e.target.result;
            console.log('File content:', content); // Debug statement
            try {
                const response = await fetch('/process', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ content })
                });
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                const data = await response.json();

                // Create a blob from the output content
                const blob = new Blob([data.processedContent], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);

                // Automatically download the file
                const link = document.createElement('a');
                link.href = url;
                link.download = 'Processed_TTPs.txt';
                link.click();
                // Clean up
                URL.revokeObjectURL(url);

                document.getElementById('results').innerText = 'File uploaded and processed: ' + file.name;
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('results').innerText = 'There was an error processing the file.';
            }
        };
        reader.readAsText(file);
    } else {
        alert('Please select a file to upload.');
    }
});
