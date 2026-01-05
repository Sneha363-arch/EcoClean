// Chat Bot Functionality
const chatToggle = document.getElementById('chatToggle');
const chatWindow = document.getElementById('chatWindow');
const closeChat = document.getElementById('closeChat');
const userInput = document.getElementById('userInput');
const sendMessage = document.getElementById('sendMessage');
const chatMessages = document.getElementById('chatMessages');

// Chat bot responses
const responses = {
    'hello': 'Hello! I\'m your EcoClean Assistant. How can I help you today?',
    'hi': 'Hi there! I\'m your EcoClean Assistant. What would you like to know?',
    'help': 'I can help you with:\n1. Understanding digital waste\n2. Using our platform\n3. Email cleanup\n4. File optimization\n5. Carbon footprint reduction\nWhat would you like to know more about?',
    'how to use': 'Here\'s how to use our platform:\n\n1. Get Started: Select a folder to analyze your files\n2. Duplicate Detection: Find and remove duplicate files\n3. Carbon Analysis: Check your digital carbon footprint\n4. Email Cleanup: Optimize your email storage\n5. SDG-12 Impact: Track your sustainable consumption\n\nWhich feature would you like to know more about?',
    'what is digital waste': 'Digital waste refers to unnecessary data stored on your devices and cloud storage that consumes energy and resources. This includes:\n\n- Duplicate files\n- Unused applications\n- Old emails and attachments\n- Temporary files\n- Unused cloud storage\n\nOur platform helps you identify and clean up this waste to reduce your digital carbon footprint.',
    'services': 'EcoClean offers several services to help manage your digital waste:\n\n1. Duplicate File Detection: Find and remove duplicate files\n2. Carbon Emission Analysis: Measure your digital carbon footprint\n3. Email Cleanup: Optimize email storage and attachments\n4. SDG-12 Impact Tracking: Monitor sustainable digital consumption\n\nWould you like to know more about any specific service?',
    'duplicate files': 'Our duplicate file detection helps you:\n- Find identical files across your system\n- Identify similar files with different names\n- Analyze storage space wasted by duplicates\n- Safely remove unnecessary duplicates\n\nTry our Duplicate Files Detection section to get started!',
    'carbon footprint': 'Digital activities contribute to carbon emissions through:\n- Data storage and servers\n- Email storage and transmission\n- File transfers and downloads\n- Cloud computing\n\nUse our Carbon Emission Analysis tool to measure and reduce your digital carbon footprint.',
    'email cleanup': 'Our email cleanup service helps you:\n- Identify large email attachments\n- Find duplicate emails\n- Optimize email storage\n- Reduce email-related carbon emissions\n\nVisit the Email Cleanup section to optimize your inbox!',
    'sdg 12': 'SDG-12 focuses on sustainable consumption and production. Our platform helps you:\n- Track digital resource consumption\n- Optimize storage usage\n- Reduce digital waste\n- Make sustainable digital choices\n\nCheck our SDG-12 Impact section to learn more!',
    'what are the benefits': 'Benefits of using EcoClean:\n\n1. Environmental Impact:\n- Reduce digital carbon footprint\n- Lower energy consumption\n- Minimize data center impact\n\n2. Storage Optimization:\n- Free up valuable storage space\n- Improve system performance\n- Better file organization\n\n3. Cost Savings:\n- Reduce storage costs\n- Lower energy bills\n- Optimize resource usage',
    'how to reduce carbon': 'To reduce your digital carbon footprint:\n\n1. Clean up duplicate files\n2. Remove unused applications\n3. Optimize email storage\n4. Archive old files\n5. Use cloud storage efficiently\n\nOur tools help you identify and clean up these areas automatically!',
    'what is sdg 12': 'SDG-12 (Sustainable Development Goal 12) focuses on responsible consumption and production. In digital terms, this means:\n\n- Efficient use of digital resources\n- Reducing digital waste\n- Sustainable data management\n- Responsible digital consumption\n\nOur platform helps you align with these goals!',
    'how to optimize storage': 'To optimize your storage:\n\n1. Use our Duplicate Detection tool\n2. Analyze large files\n3. Clean up email attachments\n4. Remove unused applications\n5. Archive old files\n\nStart with our "Get Started" section to analyze your storage!',
    'what is carbon analysis': 'Carbon Analysis helps you understand your digital carbon footprint by:\n\n- Measuring storage usage\n- Calculating energy consumption\n- Identifying high-impact files\n- Suggesting optimization options\n\nTry our Carbon Emission Analysis tool to get started!',
    'how to clean emails': 'To clean up your emails:\n\n1. Connect your email account\n2. Analyze storage usage\n3. Identify large attachments\n4. Find duplicate emails\n5. Optimize storage\n\nUse our Email Cleanup section to begin!',
    'what is sustainable digital waste management': 'Sustainable Digital Waste Management is the practice of efficiently managing digital resources to minimize environmental impact. It includes:\n\n1. Identifying and removing unnecessary data\n2. Optimizing storage usage\n3. Reducing energy consumption\n4. Minimizing carbon emissions\n5. Promoting responsible digital consumption\n\nOur platform helps you implement these practices effectively!',
    'importance of sustainable digital waste management': 'Sustainable Digital Waste Management is crucial because:\n\n1. Environmental Impact:\n- Reduces energy consumption in data centers\n- Lowers carbon emissions\n- Minimizes electronic waste\n\n2. Resource Efficiency:\n- Optimizes storage space\n- Reduces server load\n- Improves system performance\n\n3. Cost Benefits:\n- Lower storage costs\n- Reduced energy bills\n- Better resource utilization\n\n4. Future Sustainability:\n- Preserves digital resources\n- Supports green computing\n- Promotes responsible technology use',
    'what is digital footprint': 'A digital footprint is the total amount of data and digital activities you generate, including:\n\n1. Data Storage:\n- Files and documents\n- Photos and videos\n- Emails and attachments\n\n2. Online Activities:\n- Social media posts\n- Downloads and uploads\n- Cloud storage usage\n\n3. System Resources:\n- Applications and software\n- Temporary files\n- Cache and cookies\n\nManaging your digital footprint is essential for sustainability!',
    'importance of digital footprint': 'Understanding and managing your digital footprint is important because:\n\n1. Environmental Impact:\n- Data centers consume 2% of global electricity\n- Each GB of storage produces 0.2 kg CO2 annually\n- Unused files waste energy and resources\n\n2. System Performance:\n- Faster system operations\n- Better storage management\n- Reduced risk of data loss\n\n3. Cost Efficiency:\n- Lower storage costs\n- Reduced energy consumption\n- Optimized resource usage\n\n4. Security Benefits:\n- Better data organization\n- Easier backup management\n- Improved privacy control',
    'impact of co2 emission on environment': 'CO2 emissions from digital activities impact the environment in several ways:\n\n1. Climate Change:\n- Contributes to global warming\n- Affects weather patterns\n- Increases carbon levels\n\n2. Energy Consumption:\n- Data centers use massive amounts of electricity\n- Cooling systems require additional energy\n- Server maintenance increases emissions\n\n3. Resource Depletion:\n- Accelerates natural resource consumption\n- Increases electronic waste\n- Impacts biodiversity\n\n4. Solutions:\n- Optimize digital storage\n- Reduce unnecessary data\n- Use energy-efficient systems\n- Implement sustainable practices',
    'how to reduce co2 emissions': 'You can reduce CO2 emissions through digital activities by:\n\n1. File Management:\n- Remove duplicate files\n- Archive old data\n- Clean up unused applications\n\n2. Email Optimization:\n- Delete unnecessary emails\n- Remove large attachments\n- Use email cleanup tools\n\n3. Storage Practices:\n- Use cloud storage efficiently\n- Implement data compression\n- Regular cleanup routines\n\n4. System Maintenance:\n- Update software regularly\n- Optimize system settings\n- Monitor resource usage\n\nOur platform helps you implement these practices!',
    'why is digital sustainability important': 'Digital sustainability is crucial because:\n\n1. Environmental Protection:\n- Reduces carbon emissions\n- Minimizes energy waste\n- Preserves natural resources\n\n2. Economic Benefits:\n- Lower operational costs\n- Improved efficiency\n- Better resource allocation\n\n3. Social Impact:\n- Promotes responsible technology use\n- Supports green initiatives\n- Creates awareness\n\n4. Future Benefits:\n- Sustainable digital ecosystem\n- Reduced environmental impact\n- Better resource management\n\nStart your sustainable digital journey with EcoClean!',
    'how does digital waste affect environment': 'Digital waste affects the environment through:\n\n1. Energy Consumption:\n- Increased data center power usage\n- Higher cooling requirements\n- More server maintenance\n\n2. Carbon Emissions:\n- Higher CO2 levels\n- Increased greenhouse gases\n- Climate change impact\n\n3. Resource Usage:\n- More electronic waste\n- Higher water consumption\n- Increased raw material use\n\n4. Solutions:\n- Regular digital cleanup\n- Efficient storage management\n- Sustainable practices\n\nOur platform helps you minimize these impacts!',
    'default': 'I\'m not sure about that. Could you please rephrase your question? You can ask me about:\n- How to use the platform\n- What is digital waste\n- Our services\n- Duplicate files\n- Carbon footprint\n- Email cleanup\n- SDG-12'
};

// Toggle chat window
chatToggle.addEventListener('click', () => {
    chatWindow.classList.add('active');
    userInput.focus();
});

closeChat.addEventListener('click', () => {
    chatWindow.classList.remove('active');
});

// Close chat window when clicking outside
document.addEventListener('click', (e) => {
    if (!chatWindow.contains(e.target) && !chatToggle.contains(e.target)) {
        chatWindow.classList.remove('active');
    }
});

// Handle message sending
sendMessage.addEventListener('click', () => {
    const message = userInput.value.trim();
    if (message) {
        addMessage(message, 'user');
        userInput.value = '';
        processUserMessage(message);
    }
});

// Handle enter key
userInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage.click();
    }
});

// Add message to chat
function addMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}-message`;
    messageDiv.textContent = message;
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function processUserMessage(message) {
    const lowerMessage = message.toLowerCase();
    let response = '';

    if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
        response = responses['hello'];
    } else if (lowerMessage.includes('help') || lowerMessage.includes('what can you do')) {
        response = responses['help'];
    } else if (lowerMessage.includes('how to use')) {
        response = responses['how to use'];
    } else if (lowerMessage.includes('what is digital waste')) {
        response = responses['what is digital waste'];
    } else if (lowerMessage.includes('services')) {
        response = responses['services'];
    } else if (lowerMessage.includes('duplicate files')) {
        response = responses['duplicate files'];
    } else if (lowerMessage.includes('carbon footprint')) {
        response = responses['carbon footprint'];
    } else if (lowerMessage.includes('email cleanup')) {
        response = responses['email cleanup'];
    } else if (lowerMessage.includes('sdg 12')) {
        response = responses['sdg 12'];
    } else if (lowerMessage.includes('benefits')) {
        response = responses['what are the benefits'];
    } else if (lowerMessage.includes('reduce carbon')) {
        response = responses['how to reduce carbon'];
    } else if (lowerMessage.includes('what is sdg')) {
        response = responses['what is sdg 12'];
    } else if (lowerMessage.includes('optimize storage')) {
        response = responses['how to optimize storage'];
    } else if (lowerMessage.includes('carbon analysis')) {
        response = responses['what is carbon analysis'];
    } else if (lowerMessage.includes('clean emails')) {
        response = responses['how to clean emails'];
    } else if (lowerMessage.includes('sustainable digital waste management')) {
        if (lowerMessage.includes('importance')) {
            response = responses['importance of sustainable digital waste management'];
        } else {
            response = responses['what is sustainable digital waste management'];
        }
    } else if (lowerMessage.includes('digital footprint')) {
        if (lowerMessage.includes('importance')) {
            response = responses['importance of digital footprint'];
        } else {
            response = responses['what is digital footprint'];
        }
    } else if (lowerMessage.includes('co2') || lowerMessage.includes('carbon')) {
        if (lowerMessage.includes('impact')) {
            response = responses['impact of co2 emission on environment'];
        } else if (lowerMessage.includes('reduce')) {
            response = responses['how to reduce co2 emissions'];
        }
    } else if (lowerMessage.includes('digital sustainability')) {
        response = responses['why is digital sustainability important'];
    } else if (lowerMessage.includes('digital waste') && lowerMessage.includes('affect')) {
        response = responses['how does digital waste affect environment'];
    } else {
        response = responses['default'];
    }

    setTimeout(() => addMessage(response, 'bot'), 500);
}

// File Analysis Functionality
const uploadForm = document.getElementById('uploadForm');
const folderInput = document.getElementById('folderInput');

uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const files = folderInput.files;
    if (files.length === 0) {
        alert('Please select a folder to analyze');
        return;
    }

    // Show loading state
    const submitButton = uploadForm.querySelector('button');
    const originalText = submitButton.textContent;
    submitButton.disabled = true;
    submitButton.textContent = 'Analyzing...';

    try {
        const analysis = await analyzeFiles(files);
        displayResults(analysis);
    } catch (error) {
        console.error('Error analyzing files:', error);
        alert('An error occurred while analyzing files. Please try again.');
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
});

async function analyzeFiles(files) {
    const analysis = {
        largeFiles: [],
        duplicateFiles: [],
        leastAccessed: [],
        totalSize: 0,
        carbonFootprint: 0
    };

    const fileMap = new Map(); // For duplicate detection
    const accessTimes = []; // For least accessed files

    for (const file of files) {
        // Calculate file size
        const size = file.size;
        analysis.totalSize += size;

        // Check for large files (>100MB)
        if (size > 100 * 1024 * 1024) {
            analysis.largeFiles.push({
                name: file.name,
                size: formatFileSize(size),
                path: file.webkitRelativePath
            });
        }

        // Check for duplicates using file hash
        const hash = await calculateFileHash(file);
        if (fileMap.has(hash)) {
            analysis.duplicateFiles.push({
                original: fileMap.get(hash),
                duplicate: {
                    name: file.name,
                    path: file.webkitRelativePath
                }
            });
        } else {
            fileMap.set(hash, {
                name: file.name,
                path: file.webkitRelativePath
            });
        }

        // Store access time
        accessTimes.push({
            name: file.name,
            path: file.webkitRelativePath,
            lastAccessed: file.lastModified
        });
    }

    // Sort by last accessed time
    accessTimes.sort((a, b) => a.lastAccessed - b.lastAccessed);
    analysis.leastAccessed = accessTimes.slice(0, 5);

    // Calculate carbon footprint (simplified calculation)
    // Assuming 1GB of storage = 0.2 kg CO2 per year
    analysis.carbonFootprint = (analysis.totalSize / (1024 * 1024 * 1024)) * 0.2;

    return analysis;
}

async function calculateFileHash(file) {
    // This is a simplified hash function. In a real application,
    // you would want to use a more robust hashing algorithm
    return file.name + file.size;
}

function formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Byte';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}

function displayResults(analysis) {
    // Create results modal
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Analysis Results</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="results-section">
                        <h6>Total Storage Used</h6>
                        <p>${formatFileSize(analysis.totalSize)}</p>
                    </div>
                    <div class="results-section">
                        <h6>Estimated Carbon Footprint</h6>
                        <p>${analysis.carbonFootprint.toFixed(2)} kg CO2/year</p>
                    </div>
                    <div class="results-section">
                        <h6>Large Files (>100MB)</h6>
                        <ul>
                            ${analysis.largeFiles.map(file => `
                                <li>${file.name} (${file.size})</li>
                            `).join('')}
                        </ul>
                    </div>
                    <div class="results-section">
                        <h6>Least Accessed Files</h6>
                        <ul>
                            ${analysis.leastAccessed.map(file => `
                                <li>${file.name}</li>
                            `).join('')}
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();

    // Remove modal when closed
    modal.addEventListener('hidden.bs.modal', () => {
        document.body.removeChild(modal);
    });
}

// Add smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Duplicate Files Functionality
const duplicateForm = document.getElementById('duplicateForm');
const duplicateFolderInput = document.getElementById('duplicateFolderInput');
const duplicateResults = document.getElementById('duplicateResults');
const duplicateList = document.getElementById('duplicateList');
const cleanupDuplicates = document.getElementById('cleanupDuplicates');

duplicateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const files = duplicateFolderInput.files;
    if (files.length === 0) {
        alert('Please select a folder to scan');
        return;
    }

    const submitButton = duplicateForm.querySelector('button');
    submitButton.disabled = true;
    submitButton.textContent = 'Scanning...';

    try {
        const duplicates = await findDuplicates(files);
        displayDuplicates(duplicates);
        duplicateResults.style.display = 'block';
    } catch (error) {
        console.error('Error scanning duplicates:', error);
        alert('An error occurred while scanning for duplicates');
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Scan for Duplicates';
    }
});

async function findDuplicates(files) {
    const fileMap = new Map();
    const duplicates = [];

    for (const file of files) {
        const hash = await calculateFileHash(file);
        if (fileMap.has(hash)) {
            duplicates.push({
                original: fileMap.get(hash),
                duplicate: {
                    name: file.name,
                    path: file.webkitRelativePath,
                    size: file.size
                }
            });
        } else {
            fileMap.set(hash, {
                name: file.name,
                path: file.webkitRelativePath,
                size: file.size
            });
        }
    }

    return duplicates;
}

function displayDuplicates(duplicates) {
    duplicateList.innerHTML = '';
    
    if (duplicates.length === 0) {
        duplicateList.innerHTML = `
            <div class="alert alert-success text-center">
                <i class="fas fa-check-circle me-2"></i>
                No duplicate files found in the selected folder.
            </div>
        `;
        return;
    }

    duplicates.forEach((dup, index) => {
        const item = document.createElement('div');
        item.className = 'list-group-item';
        item.innerHTML = `
            <div>
                <strong>Original:</strong> ${dup.original.name}<>
                <strong>Duplicate:</strong> ${dup.duplicate.name}<br>
                <small class="text-muted">Size: ${formatFileSize(dup.duplicate.size)}</small>
            </div>
            <div class="form-check">
                <input class="form-check-input" type="checkbox" value="${index}" id="dup${index}">
                <label class="form-check-label" for="dup${index}">Select</label>
            </div>
        `;
        duplicateList.appendChild(item);
    });
}

cleanupDuplicates.addEventListener('click', async () => {
    const selectedDuplicates = Array.from(duplicateList.querySelectorAll('input:checked')).map(input => parseInt(input.value));
    if (selectedDuplicates.length === 0) {
        alert('Please select duplicates to clean up');
        return;
    }

    const button = cleanupDuplicates;
    const originalText = addLoadingState(button);

    try {
        // Simulate cleanup process
        await new Promise(resolve => setTimeout(resolve, 1500));
        showSuccessMessage('Duplicate files cleaned up successfully!');
        duplicateResults.style.display = 'none';
        duplicateForm.reset();
    } catch (error) {
        console.error('Error cleaning up duplicates:', error);
        alert('An error occurred while cleaning up duplicates');
    } finally {
        removeLoadingState(button, originalText);
    }
});

// Carbon Emission Analysis
const carbonForm = document.getElementById('carbonForm');
const carbonFolderInput = document.getElementById('carbonFolderInput');
const carbonResults = document.getElementById('carbonResults');
const carbonDetails = document.getElementById('carbonDetails');
const optimizeCarbon = document.getElementById('optimizeCarbon');

carbonForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const files = carbonFolderInput.files;
    if (files.length === 0) {
        alert('Please select a folder to analyze');
        return;
    }

    const submitButton = carbonForm.querySelector('button');
    submitButton.disabled = true;
    submitButton.textContent = 'Analyzing...';

    try {
        const analysis = await analyzeCarbonImpact(files);
        displayCarbonAnalysis(analysis);
        carbonResults.style.display = 'block';
    } catch (error) {
        console.error('Error analyzing carbon impact:', error);
        alert('An error occurred while analyzing carbon impact');
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Analyze Carbon Impact';
    }
});

async function analyzeCarbonImpact(files) {
    let totalSize = 0;
    const fileTypes = new Map();
    const lastAccessed = [];

    for (const file of files) {
        totalSize += file.size;
        
        // Group by file type
        const type = file.name.split('.').pop().toLowerCase();
        fileTypes.set(type, (fileTypes.get(type) || 0) + 1);

        // Track last accessed files
        lastAccessed.push({
            name: file.name,
            lastAccessed: file.lastModified,
            size: file.size
        });
    }

    // Calculate carbon footprint (simplified)
    const carbonFootprint = (totalSize / (1024 * 1024 * 1024)) * 0.2; // 0.2 kg CO2 per GB per year

    // Sort by last accessed
    lastAccessed.sort((a, b) => a.lastAccessed - b.lastAccessed);

    return {
        totalSize,
        carbonFootprint,
        fileTypes: Array.from(fileTypes.entries()),
        leastAccessed: lastAccessed.slice(0, 5)
    };
}

function displayCarbonAnalysis(analysis) {
    carbonDetails.innerHTML = `
        <div class="carbon-metric">
            <span>Total Storage Used:</span>
            <span>${formatFileSize(analysis.totalSize)}</span>
        </div>
        <div class="carbon-metric">
            <span>Estimated Carbon Footprint:</span>
            <span>${analysis.carbonFootprint.toFixed(2)} kg CO2/year</span>
        </div>
        <div class="carbon-metric">
            <span>File Types Distribution:</span>
            <span>${analysis.fileTypes.map(([type, count]) => `${type}: ${count}`).join(', ')}</span>
        </div>
        <div class="carbon-metric">
            <span>Least Accessed Files:</span>
            <span>${analysis.leastAccessed.map(file => file.name).join(', ')}</span>
        </div>
    `;
}

optimizeCarbon.addEventListener('click', async () => {
    const button = optimizeCarbon;
    const originalText = addLoadingState(button);

    try {
        // Simulate optimization process
        await new Promise(resolve => setTimeout(resolve, 1500));
        showSuccessMessage('Storage optimized successfully!');
        carbonResults.style.display = 'none';
        carbonForm.reset();
    } catch (error) {
        console.error('Error optimizing storage:', error);
        alert('An error occurred while optimizing storage');
    } finally {
        removeLoadingState(button, originalText);
    }
});

// Utility Functions
function showSuccessMessage(message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'success-message';
    messageDiv.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <h4>Success!</h4>
        <p>${message}</p>
    `;
    document.body.appendChild(messageDiv);

    // Add overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        z-index: 999;
        animation: fadeIn 0.3s ease-out;
    `;
    document.body.appendChild(overlay);

    // Remove message and overlay after delay
    setTimeout(() => {
        messageDiv.style.animation = 'popOut 0.5s ease-out';
        overlay.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => {
            document.body.removeChild(messageDiv);
            document.body.removeChild(overlay);
        }, 500);
    }, 3000);
}

// Add scroll animation for navbar
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// Add animation to section headers
const observerOptions = {
    threshold: 0.1
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('animate__animated', 'animate__fadeInUp');
        }
    });
}, observerOptions);

document.querySelectorAll('.section-header').forEach(header => {
    observer.observe(header);
});

// Add loading animation to buttons
function addLoadingState(button) {
    const originalText = button.textContent;
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span> Processing...';
    return originalText;
}

function removeLoadingState(button, originalText) {
    button.disabled = false;
    button.textContent = originalText;
}

// Add animation to feature cards
document.querySelectorAll('.feature-card').forEach(card => {
    observer.observe(card);
});

// Add smooth reveal animation to sections
document.querySelectorAll('section').forEach(section => {
    observer.observe(section);
});

// Toast Notification
document.addEventListener('DOMContentLoaded', function() {
    const optimizeButton = document.getElementById('optimizeCarbon');
    const optimizeToast = new bootstrap.Toast(document.getElementById('optimizeToast'));

    if (optimizeButton) {
        optimizeButton.addEventListener('click', function() {
            optimizeToast.show();
        });
    }
});

// Email Section Functionality
document.addEventListener('DOMContentLoaded', function() {
    const emailProceedButton = document.querySelector('#emailForm button[type="on-click"]');
    const optimizeToast = new bootstrap.Toast(document.getElementById('optimizeToast'));

    if (emailProceedButton) {
        emailProceedButton.addEventListener('click', function(e) {
            e.preventDefault();
            optimizeToast.show();
        });
    }
});
