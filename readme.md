# Overview

C-SENTINAL is a comprehensive Flask-based cybersecurity web application designed for security professionals, researchers, and enthusiasts. The platform provides a suite of 10 security tools including hash calculation, file encryption/decryption, password cracking, vulnerability scanning, malware detection, password strength analysis, comprehensive network diagnostic tools and stegnography tool. The application features a dark Matrix-themed UI with neon green accents and animated background effects, creating an immersive cybersecurity environment.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Theme**: Dark Matrix theme with neon green (#00ff66) accents and animated Matrix rain background
- **Framework**: Bootstrap 5.3.0 for responsive design and components
- **Styling**: Custom CSS with CSS variables for consistent theming and glowing hover effects
- **JavaScript**: Vanilla JavaScript for interactive features and Matrix rain animation
- **Responsive Design**: 3-column desktop layout that collapses to single-column on mobile devices
- **Module Navigation**: Dynamic modal system with URL parameter support for direct module access

## Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM for database operations
- **Authentication**: Replit OAuth integration with Flask-Login for session management
- **File Handling**: Werkzeug secure filename handling with 50MB upload limit
- **Security**: CSRF protection, input validation, and file MIME type restrictions
- **Architecture Pattern**: Blueprint-based modular design for scalable route organization
- **Network Operations**: Container-optimized network diagnostic tools with fallback implementations
- **Activity Logging**: Comprehensive logging system for all security operations and network diagnostics

## Database Schema
- **Users Table**: Stores user profiles with role-based access (user/admin)
- **OAuth Table**: Manages OAuth tokens and browser sessions for Replit authentication
- **Uploads Table**: Tracks file uploads with metadata (filename, size, hash)
- **Jobs Table**: Manages background tasks (password cracking, scanning) with progress tracking
- **Additional Tables**: ScanResult and ActivityLog for security operations and audit trails

## Security Modules
- **Hash Calculator**: MD5, SHA-1, SHA-256, SHA-512 generation and comparison
- **File Encryption**: AES encryption/decryption with PBKDF2 key derivation
- **Password Cracker**: Brute force attack simulation for PDF, ZIP, DOCX files with real-time progress
- **URL Scanner**: Basic safety checks for suspicious patterns and connectivity
- **Vulnerability Scanner**: SQLi/XSS detection and passive security analysis
- **Malware Scanner**: File analysis for potential threats
- **Hash Comparison**: Side-by-side hash comparison for file integrity verification
- **Password Strength Analyzer**: Comprehensive password security analysis with entropy calculation, pattern detection, and detailed recommendations
- **Network Tools**: Comprehensive network diagnostic utilities including ping, DNS lookup, port scanning, traceroute, WHOIS lookup, and network information analysis

## Authorization System
- **Role-based Access**: User and admin roles with different permission levels
- **Admin Panel**: System monitoring, user management, and activity logging
- **Session Management**: Persistent sessions with proper logout handling

# External Dependencies

## Core Framework Dependencies
- **Flask**: Web framework with SQLAlchemy extension for database ORM
- **Flask-Login**: User session management and authentication
- **Flask-Dance**: OAuth integration specifically configured for Replit authentication
- **Werkzeug**: WSGI utilities including ProxyFix for HTTPS URL generation

## Frontend Libraries
- **Bootstrap 5.3.0**: CSS framework from CDN for responsive design
- **Font Awesome 6.4.0**: Icon library from CDN for UI elements

## Cryptography Libraries
- **cryptography**: AES encryption/decryption with Fernet and PBKDF2 key derivation
- **hashlib**: Built-in Python library for hash calculations

## File Processing Libraries
- **PyPDF2**: PDF file manipulation and password verification
- **python-docx**: Microsoft Word document processing
- **zipfile**: Built-in Python library for ZIP archive handling

## HTTP and Security
- **requests**: HTTP client library for URL scanning and external API calls
- **JWT**: JSON Web Token handling for authentication tokens
- **bcrypt**: Password hashing (implied for secure authentication)

## Network Diagnostic Tools
- **socket**: Built-in Python library for network connections and port scanning
- **subprocess**: System command execution for network utilities
- **re**: Regular expressions for parsing network command outputs
- **time**: Timing measurements for connectivity tests

## System Dependencies
- **iputils**: Network utilities package providing ping functionality
- **traceroute**: Network route tracing utility for path analysis
- **whois**: Domain registration information lookup utility
- **dnsutils**: DNS lookup and resolution utilities

## Database Configuration
- **SQLAlchemy**: Database abstraction layer with connection pooling
- **Database URL**: Configured via environment variable for flexible deployment
- **Connection Pool**: 300-second recycle time with pre-ping for connection health

## Environment Configuration
- **SESSION_SECRET**: Environment variable for Flask session encryption
- **DATABASE_URL**: Database connection string from environment
- **File Upload Directory**: Configurable upload folder with size restrictions

# Recent Changes

## Network Tools Implementation (Latest Update)
- **Complete Network Diagnostic Suite**: 6 comprehensive network tools in tabbed interface
- **Container-Optimized Implementation**: Custom implementations for container environments without raw socket access
- **Ping Tool**: TCP connectivity testing with timing statistics and packet loss calculation
- **DNS Lookup**: Multi-record type resolution (A, AAAA, MX, NS, TXT, CNAME)
- **Port Scanner**: TCP port scanning with configurable port ranges (security limited to 50 ports)
- **Traceroute**: Network path analysis with estimated route information and actual connectivity testing
- **WHOIS Lookup**: Domain information retrieval with HTTP fallback when traditional WHOIS unavailable
- **Network Info**: Local network status and connectivity analysis
- **Professional UI**: Bootstrap 5 tabbed interface with real-time results and error handling
- **Activity Logging**: All network operations logged for security monitoring
- **Module Navigation**: Enhanced home page integration with URL parameter redirection to dashboard
- **Error Resilience**: Comprehensive fallback mechanisms for constrained environments

## Security & Performance Features
- **Input Validation**: All network inputs sanitized and validated
- **Rate Limiting**: Port scanning limited to prevent abuse
- **Timeout Protection**: All network operations have configurable timeouts
- **Fallback Implementations**: Alternative methods when system commands unavailable
- **Real-time Results**: Dynamic result display with formatted output and statistics