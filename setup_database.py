#!/usr/bin/env python3
"""
Database setup script for DASH (Disaster Assistance & Support Hub)
Run this script to create the MySQL database and tables
"""

import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

def create_database():
    """Create the DASH database if it doesn't exist"""
    try:
        # Connect to MySQL server (without specifying database)
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password='password',  # Change this to your MySQL password
            charset='utf8mb4'
        )
        
        with connection.cursor() as cursor:
            # Create database
            cursor.execute("CREATE DATABASE IF NOT EXISTS dash_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            print("✅ Database 'dash_db' created successfully")
            
        connection.close()
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        print("Please make sure MySQL is running and you have the correct credentials")
        return False
    
    return True

def create_demo_data():
    """Create demo data for testing"""
    try:
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password='password',  # Change this to your MySQL password
            database='dash_db',
            charset='utf8mb4'
        )
        
        with connection.cursor() as cursor:
            # Insert demo bulletin posts
            demo_posts = [
                ("Emergency Weather Alert", "Heavy rainfall expected in the next 2 hours. Please stay indoors and avoid flooded areas.", "warning", "urgent"),
                ("Medical Camp Location", "Temporary medical camp set up at Central Park. Open 24/7 for emergency medical assistance.", "announcement", "high"),
                ("Road Closure Update", "Main Street is closed due to flooding. Use alternative routes via Oak Avenue.", "instruction", "normal"),
                ("Evacuation Center", "Community Center is now open as evacuation center. Food and shelter available.", "announcement", "high"),
                ("Power Restoration", "Power has been restored in downtown area. Other areas will follow soon.", "update", "normal")
            ]
            
            for title, content, post_type, priority in demo_posts:
                cursor.execute("""
                    INSERT INTO bulletin_post (author_id, title, content, post_type, priority, created_at)
                    VALUES (1, %s, %s, %s, %s, NOW())
                """, (title, content, post_type, priority))
            
            # Insert demo notifications
            demo_notifications = [
                (2, "Weather Warning", "Severe weather alert: Heavy rain expected", "weather"),
                (2, "Road Block", "Main Street blocked due to flooding", "roadblock"),
                (2, "Medical Camp", "Medical assistance available at Central Park", "medical_camp"),
                (3, "SOS Alert", "Emergency assistance requested nearby", "sos"),
                (2, "Evacuation Notice", "Evacuation center open at Community Center", "evacuation")
            ]
            
            for user_id, title, message, notif_type in demo_notifications:
                cursor.execute("""
                    INSERT INTO notification (user_id, title, message, notification_type, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (user_id, title, message, notif_type))
            
            connection.commit()
            print("✅ Demo data created successfully")
            
        connection.close()
        
    except Exception as e:
        print(f"❌ Error creating demo data: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🚀 Setting up DASH Database...")
    print("=" * 50)
    
    if create_database():
        print("\n📊 Creating demo data...")
        create_demo_data()
        
        print("\n✅ Database setup completed!")
        print("\nDemo accounts:")
        print("👤 Admin: username=admin, password=admin123")
        print("👤 User: username=user1, password=user123")
        print("👤 Rescue Team: username=rescue1, password=rescue123")
        print("\n🌐 Start the application with: python app.py")
    else:
        print("\n❌ Database setup failed!")
        print("Please check your MySQL connection and try again.")
