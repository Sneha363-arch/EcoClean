-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS ecoclean_db;

-- Drop user if exists and recreate with native password authentication
DROP USER IF EXISTS 'root'@'localhost';
CREATE USER 'rooteco'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Eco123@#';

-- Grant privileges
GRANT ALL PRIVILEGES ON ecoclean_db.* TO 'rooteco'@'localhost';
FLUSH PRIVILEGES; 