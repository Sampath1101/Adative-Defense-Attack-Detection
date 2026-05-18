#!/usr/bin/env python3
"""
Fix template location issue - Copy dashboard.html to correct location
"""

import os
import shutil

def fix_templates():
    """Copy template to correct location"""
    print("\n" + "="*60)
    print("  Template Location Fix")
    print("="*60 + "\n")
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Source and destination paths
    source = os.path.join(script_dir, 'dashboard', 'templates', 'dashboard.html')
    dest_dir = os.path.join(script_dir, 'templates')
    dest = os.path.join(dest_dir, 'dashboard.html')
    
    print(f"Source: {source}")
    print(f"Destination: {dest}")
    print()
    
    # Create destination directory
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"✓ Created directory: {dest_dir}")
    else:
        print(f"✓ Directory exists: {dest_dir}")
    
    # Check if source exists
    if not os.path.exists(source):
        print(f"\n✗ ERROR: Source template not found!")
        print(f"  Expected: {source}")
        print(f"\n  Please ensure the file exists.")
        return False
    
    print(f"✓ Source template found")
    
    # Copy template
    try:
        shutil.copy2(source, dest)
        print(f"✓ Template copied successfully!")
        print(f"\n  From: {source}")
        print(f"  To:   {dest}")
        
        # Verify
        if os.path.exists(dest):
            size = os.path.getsize(dest)
            print(f"\n✓ Verification: Template exists ({size} bytes)")
            return True
        else:
            print(f"\n✗ ERROR: Template copy failed!")
            return False
    
    except Exception as e:
        print(f"\n✗ ERROR: Failed to copy template")
        print(f"  {str(e)}")
        return False

def verify_structure():
    """Verify directory structure"""
    print("\n" + "="*60)
    print("  Verifying Directory Structure")
    print("="*60 + "\n")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    required = {
        'templates': os.path.join(script_dir, 'templates'),
        'templates/dashboard.html': os.path.join(script_dir, 'templates', 'dashboard.html'),
        'dashboard': os.path.join(script_dir, 'dashboard'),
        'ml': os.path.join(script_dir, 'ml'),
        'data': os.path.join(script_dir, 'data'),
        'logs': os.path.join(script_dir, 'logs'),
        'app.py': os.path.join(script_dir, 'app.py'),
        'config.py': os.path.join(script_dir, 'config.py'),
    }
    
    all_ok = True
    for name, path in required.items():
        if os.path.exists(path):
            print(f"✓ {name}")
        else:
            print(f"✗ {name} - MISSING")
            all_ok = False
            
            # Create directories
            if '/' not in name and name not in ['app.py', 'config.py', 'templates/dashboard.html']:
                os.makedirs(path, exist_ok=True)
                print(f"  Created: {path}")
    
    return all_ok

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Advanced IDS - Template Fix Tool")
    print("="*60)
    
    # Fix templates
    success = fix_templates()
    
    # Verify structure
    verify_structure()
    
    # Summary
    print("\n" + "="*60)
    if success:
        print("✓ Template fix completed successfully!")
        print("\nNext steps:")
        print("1. Run: python app.py")
        print("2. Open: http://localhost:5000")
        print("\nThe dashboard should now load without errors!")
    else:
        print("✗ Template fix failed!")
        print("\nTroubleshooting:")
        print("1. Make sure you're in the project directory")
        print("2. Verify dashboard/templates/dashboard.html exists")
        print("3. Check file permissions")
    print("="*60 + "\n")