// JavaScript for file upload functionality
document.addEventListener('DOMContentLoaded', (event) => {
    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('file');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    dropArea.addEventListener('drop', handleDrop, false);

    dropArea.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        const files = fileInput.files;
        handleFiles(files);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        dropArea.classList.add('highlight');
    }

    function unhighlight(e) {
        dropArea.classList.remove('highlight');
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        fileInput.files = files;
        handleFiles(files);
    }

    function handleFiles(files) {
        const file = files[0];
        const fileNameDisplay = document.createElement('p');
        fileNameDisplay.textContent = `Selected file: ${file.name}`;
        dropArea.innerHTML = '';
        dropArea.appendChild(fileNameDisplay);
    }
});
