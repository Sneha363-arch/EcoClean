const scriptURL = "https://script.google.com/macros/s/AKfycbzDWgp4zJ-sB8XOGvDHs-nrgD5lPbrofZJoEs03s2tCPxe8wCNH1qC_qWcQhWvVFhANVQ/exec";

// Calculate carbon emission based on email size and age
function calculateCarbonEmission(emailDate) {
    // Average email size is around 75KB
    const emailSizeKB = 75;
    // Carbon emission per KB is approximately 0.0000001 kg CO2
    const carbonPerKB = 0.0000001;
    // Calculate age in days
    const emailDateObj = new Date(emailDate);
    const today = new Date();
    const ageInDays = Math.floor((today - emailDateObj) / (1000 * 60 * 60 * 24));
    
    // Calculate total carbon emission
    const carbonEmission = emailSizeKB * carbonPerKB * (1 + ageInDays * 0.01); // Increases slightly with age
    
    return carbonEmission.toFixed(6);
}

function showNotification(message) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.style.display = 'block';
    
    // Hide notification after 3 seconds
    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000);
}

let emailToDelete = null;

function showDeleteModal(emailId) {
    const modal = document.getElementById('deleteModal');
    emailToDelete = emailId;
    modal.style.display = 'flex';
}

function hideDeleteModal() {
    const modal = document.getElementById('deleteModal');
    modal.style.display = 'none';
    emailToDelete = null;
}

async function fetchEmails() {
    console.log("Fetching emails...");
    const emailList = document.getElementById("email-list");
    const loadBtn = document.getElementById('cleanupBtn');
    
    // Add loading state
    loadBtn.classList.add('loading');
    emailList.innerHTML = "<div class='loading'>Loading emails...</div>";

    try {
        const response = await fetch(`${scriptURL}?action=getEmails`);
        console.log("Response status:", response.status);

        const emails = await response.json();
        console.log("Emails received:", emails);

        emailList.innerHTML = "";

        if (emails.length === 0) {
            emailList.innerHTML = "<p>No emails found.</p>";
            return;
        }

        emails.forEach(email => {
            const carbonEmission = calculateCarbonEmission(email.date);
            let emailItem = document.createElement("div");
            emailItem.classList.add("email-item");
            emailItem.innerHTML = `
                <p><strong>Subject:</strong> ${email.subject}</p>
                <p><strong>From:</strong> ${email.sender}</p>
                <p><strong>Date:</strong> ${email.date}</p>
                <div class="carbon-info">
                    <strong>Carbon Emission:</strong> ${carbonEmission} kg CO2
                </div>
                <button class="delete-btn" onclick="showDeleteModal('${email.id}')">Delete</button>
            `;
            emailList.appendChild(emailItem);
        });
    } catch (error) {
        console.error("Error fetching emails:", error);
        emailList.innerHTML = "<p>Error loading emails.</p>";
    } finally {
        // Remove loading state
        loadBtn.classList.remove('loading');
    }
}

async function deleteEmail(emailId) {
    console.log("Deleting email:", emailId);

    try {
        const response = await fetch(`${scriptURL}?action=deleteEmail&emailId=${emailId}`);
        const result = await response.text();
        console.log("Delete response:", result);
        
        if (result === "Deleted") {
            const emailItem = document.querySelector(`[onclick="showDeleteModal('${emailId}')"]`).parentElement;
            emailItem.remove();
            showNotification("Email deleted successfully!");
            hideDeleteModal();
        } else {
            showNotification(result);
        }
    } catch (error) {
        console.error("Error deleting email:", error);
        showNotification("Error deleting email");
    }
}

// Event Listeners
document.getElementById('confirmDelete').addEventListener('click', () => {
    if (emailToDelete) {
        deleteEmail(emailToDelete);
    }
});

document.getElementById('cancelDelete').addEventListener('click', hideDeleteModal);

// Close modal when clicking outside
window.addEventListener('click', (event) => {
    const modal = document.getElementById('deleteModal');
    if (event.target === modal) {
        hideDeleteModal();
    }
});

// Cleanup button event listener
document.getElementById('cleanupBtn').addEventListener('click', fetchEmails);

// Fetch emails when the page loads
window.onload = fetchEmails; 