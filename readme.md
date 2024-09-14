# m-core-firewall

`m-core-firewall` is a Node.js package designed to enhance the security of your Express applications. It provides a robust firewall solution to protect against common vulnerabilities such as rate limiting, SQL injection, and XSS attacks.

## Installation

To install `m-core-firewall`, run the following command:

```bash
npm install m-core-firewall


Usage
Basic Setup

Import and use m-core-firewall in your main application file (e.g., app.js):

const express = require('express');
const mCoreFirewall = require('m-core-firewall');

const app = express();

// Configure the firewall
app.use(mCoreFirewall({
    // Optional configuration options
    rateLimit: { maxRequests: 5, windowMs: 15 * 60 * 1000 }, // Example rate limit settings
    sqlInjection: true, // Enable SQL injection protection
    xss: true // Enable XSS protection
}));

// Your routes and middleware
app.get('/test', (req, res) => {
    res.send('Hello, World!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


Configuration Options

You can configure m-core-firewall with the following options:

    rateLimit: An object to set rate limiting parameters.
        maxRequests: Maximum number of requests allowed.
        windowMs: Time window for rate limiting in milliseconds.

    sqlInjection: Boolean value to enable or disable SQL injection protection.

    xss: Boolean value to enable or disable XSS protection.

Example

Here’s an example with custom settings:

const express = require('express');
const mCoreFirewall = require('m-core-firewall');

const app = express();

app.use(mCoreFirewall({
    rateLimit: { maxRequests: 10, windowMs: 60 * 60 * 1000 }, // 10 requests per hour
    sqlInjection: true,
    xss: true
}));

app.get('/test', (req, res) => {
    res.send('This is a secure endpoint!');
});

const PORT = 4000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


Configuration

You can customize the firewall settings to fit your application's needs. Adjust the rateLimit, sqlInjection, and xss options according to your security requirements.
Donations

If you find this package useful and would like to support its development, consider making a donation via PayPal:

    PayPal: mohlalamim@gmail.com