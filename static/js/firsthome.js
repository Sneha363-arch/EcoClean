// Mobile Menu Toggle
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

hamburger.addEventListener('click', () => {
    navMenu.classList.toggle('active');
    hamburger.classList.toggle('active');
});

// Close mobile menu when clicking outside
document.addEventListener('click', (e) => {
    if (!navMenu.contains(e.target) && !hamburger.contains(e.target)) {
        navMenu.classList.remove('active');
        hamburger.classList.remove('active');
    }
});

// Close mobile menu when clicking a link
document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', () => {
        navMenu.classList.remove('active');
        hamburger.classList.remove('active');
    });
});

// Smooth scrolling for navigation links
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

// Form submission handling
const contactForm = document.querySelector('.contact-form');
if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();
        // Add your form submission logic here
        alert('Thank you for your message! We will get back to you soon.');
        contactForm.reset();
    });
}

// Scroll animations
const observerOptions = {
    threshold: 0.1
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
        }
    });
}, observerOptions);

// Observe all sections
document.querySelectorAll('section').forEach(section => {
    observer.observe(section);
});

// Interactive text animation
document.addEventListener('DOMContentLoaded', function() {
    const textItems = document.querySelectorAll('.text-item');
    let currentIndex = 0;
    
    // Show the first item
    textItems[0].classList.add('active');
    
    // Rotate through items
    setInterval(function() {
        textItems[currentIndex].classList.remove('active');
        currentIndex = (currentIndex + 1) % textItems.length;
        textItems[currentIndex].classList.add('active');
    }, 3000);
    
    // Add click event to make items interactive
    textItems.forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from all items
            textItems.forEach(i => i.classList.remove('active'));
            // Add active class to clicked item
            this.classList.add('active');
            // Add a pulse animation
            this.classList.add('clicked');
            setTimeout(() => {
                this.classList.remove('clicked');
            }, 500);
        });
    });
    
    // Add click event to main title
    const mainTitle = document.querySelector('.main-title');
    const contentCard = document.querySelector('.content-card');
    
    mainTitle.addEventListener('click', function() {
        // Toggle active class on main title
        this.classList.toggle('active');
        
        // Toggle highlighted class on content card
        contentCard.classList.toggle('highlighted');
        
        // If title is active, show the next text item
        if (this.classList.contains('active')) {
            textItems[currentIndex].classList.remove('active');
            currentIndex = (currentIndex + 1) % textItems.length;
            textItems[currentIndex].classList.add('active');
        }
    });
}); 