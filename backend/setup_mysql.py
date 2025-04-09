import mysql.connector
from mysql.connector import Error
import getpass

def create_database():
    """Create the MySQL database and required tables"""
    try:
        # Get MySQL connection details
        host = input("Enter MySQL host (default: localhost): ") or "localhost"
        user = input("Enter MySQL username (default: root): ") or "root"
        password = getpass.getpass("Enter MySQL password: ")
        
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database
            db_name = "endpoint_management"
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            print(f"Database '{db_name}' created successfully")
            
            # Connect to the new database
            cursor.execute(f"USE {db_name}")
            
            # Create endpoints table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(50) NOT NULL,
                computer_name VARCHAR(100),
                collection_time DATETIME NOT NULL,
                collection_status VARCHAR(20) NOT NULL,
                os_name VARCHAR(100),
                os_version VARCHAR(50),
                os_build VARCHAR(50),
                os_architecture VARCHAR(20),
                install_date DATETIME,
                last_boot DATETIME,
                manufacturer VARCHAR(100),
                model VARCHAR(100),
                serial_number VARCHAR(100),
                cpu VARCHAR(200),
                ram_gb FLOAT,
                domain VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)
            print("Table 'endpoints' created successfully")
            
            # Create software table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS software (
                id INT AUTO_INCREMENT PRIMARY KEY,
                endpoint_id INT NOT NULL,
                software_name VARCHAR(255) NOT NULL,
                version VARCHAR(100),
                vendor VARCHAR(255),
                install_date DATETIME,
                source VARCHAR(50),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
            )
            """)
            print("Table 'software' created successfully")
            
            # Create indexes
            cursor.execute("CREATE INDEX idx_ip_address ON endpoints(ip_address)")
            cursor.execute("CREATE INDEX idx_collection_time ON endpoints(collection_time)")
            cursor.execute("CREATE INDEX idx_endpoint_id ON software(endpoint_id)")
            print("Indexes created successfully")
            
            # Print connection string for app.py
            print("\n=== Database Setup Complete ===")
            print(f"Update the SQLALCHEMY_DATABASE_URI in app.py with:")
            print(f"mysql://{user}:{password}@{host}/{db_name}")
            
            cursor.close()
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            connection.close()
            print("MySQL connection closed")

if __name__ == "__main__":
    create_database()
