import sqlite3

def patch_db():
    try:
        conn = sqlite3.connect('malware_sandbox.db')
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(analysis_job)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'progress' not in columns:
            print("Adding column 'progress'...")
            cursor.execute("ALTER TABLE analysis_job ADD COLUMN progress INTEGER DEFAULT 0")
        
        if 'status_message' not in columns:
            print("Adding column 'status_message'...")
            cursor.execute("ALTER TABLE analysis_job ADD COLUMN status_message VARCHAR(255)")
            
        conn.commit()
        print("Database patched successfully.")
        conn.close()
    except Exception as e:
        print(f"Error patching database: {e}")

if __name__ == "__main__":
    patch_db()
