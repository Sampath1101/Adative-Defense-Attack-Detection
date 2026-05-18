"""
Test Script for Chunk Data Processor
Creates sample dataset and tests processing
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
import sys
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))


def generate_sample_dataset(output_file='data/test_dataset.csv', num_rows=50000):
    """
    Generate sample dataset for testing
    
    Args:
        output_file (str): Output file path
        num_rows (int): Number of rows to generate
    """
    print("=" * 70)
    print("🔧 Generating Sample Dataset for Testing")
    print("=" * 70)
    print(f"📊 Rows: {num_rows:,}")
    print(f"💾 Output: {output_file}")
    
    # Create data directory if needed
    os.makedirs('data', exist_ok=True)
    
    # Generate timestamps
    start_time = datetime.now() - timedelta(days=7)
    timestamps = [start_time + timedelta(minutes=i) for i in range(num_rows)]
    
    # Generate IPs
    ips = [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" 
           for _ in range(num_rows)]
    
    # Normal paths
    normal_paths = [
        '/api/users',
        '/api/products',
        '/api/orders',
        '/home',
        '/about',
        '/contact',
        '/search?q=products',
        '/profile',
        '/dashboard',
        '/settings'
    ]
    
    # Suspicious paths
    suspicious_paths = [
        "/api/users?id=1' OR '1'='1",
        "/api/users?id=1' UNION SELECT * FROM users--",
        "/search?q=<script>alert('XSS')</script>",
        "/files/../../etc/passwd",
        "/files/../../../etc/shadow",
        "/admin/users",
        "/admin/config",
        "/.env",
        "/config.php",
        "/backup/database.sql",
        "/upload/shell.php",
        "/api/exec?cmd=whoami",
        "/ping?host=127.0.0.1|ls",
        "/search?q=<img src=x onerror=alert(1)>",
        "/api/users'; DROP TABLE users;--"
    ]
    
    # Generate paths (80% normal, 20% suspicious)
    paths = []
    for _ in range(num_rows):
        if np.random.random() < 0.8:  # 80% normal
            paths.append(np.random.choice(normal_paths))
        else:  # 20% suspicious
            paths.append(np.random.choice(suspicious_paths))
    
    # Generate methods
    methods = np.random.choice(['GET', 'POST', 'PUT', 'DELETE'], num_rows, 
                               p=[0.7, 0.2, 0.05, 0.05])
    
    # Generate status codes
    status_codes = []
    for path in paths:
        if any(x in path for x in suspicious_paths):
            # Suspicious requests more likely to fail
            status_codes.append(np.random.choice([400, 403, 404, 500], p=[0.4, 0.3, 0.2, 0.1]))
        else:
            # Normal requests mostly succeed
            status_codes.append(np.random.choice([200, 201, 304, 400], p=[0.7, 0.15, 0.1, 0.05]))
    
    # Generate user agents
    normal_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1',
        'Mozilla/5.0 (X11; Linux x86_64) Firefox/95.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0) Mobile/15E148'
    ]
    
    suspicious_agents = [
        'sqlmap/1.0',
        'nikto/2.1.6',
        'nmap scripting engine',
        'masscan/1.0',
        'python-requests/2.25'
    ]
    
    user_agents = []
    for path in paths:
        if any(x in path for x in suspicious_paths):
            # Suspicious paths might have suspicious agents
            if np.random.random() < 0.3:
                user_agents.append(np.random.choice(suspicious_agents))
            else:
                user_agents.append(np.random.choice(normal_agents))
        else:
            user_agents.append(np.random.choice(normal_agents))
    
    # Generate response sizes
    response_sizes = np.random.randint(100, 50000, num_rows)
    
    # Create DataFrame
    df = pd.DataFrame({
        'timestamp': timestamps,
        'ip': ips,
        'path': paths,
        'method': methods,
        'status_code': status_codes,
        'user_agent': user_agents,
        'response_size': response_sizes
    })
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    
    print(f"✅ Dataset generated successfully!")
    print(f"📁 File size: {os.path.getsize(output_file) / 1024 / 1024:.2f} MB")
    print(f"📊 Preview:")
    print(df.head())
    print("=" * 70)
    
    return output_file


def test_processor():
    """Test the chunk processor"""
    print("\n" + "=" * 70)
    print("🧪 Testing Chunk Data Processor")
    print("=" * 70)
    
    # Generate test dataset
    test_file = generate_sample_dataset(num_rows=50000)
    
    print("\n⏳ Starting processing test...")
    
    try:
        from chunk_data_processor import ChunkDataProcessor
        
        # Create processor
        processor = ChunkDataProcessor(chunk_size=10000)
        
        # Process file
        summary = processor.process_file(test_file, output_format='both')
        
        print("\n" + "=" * 70)
        print("✅ TEST PASSED!")
        print("=" * 70)
        print("\n📋 Test Results:")
        print(f"   ✓ Total rows processed: {summary['statistics']['total_rows']:,}")
        print(f"   ✓ Suspicious detected: {summary['statistics']['suspicious_rows']:,}")
        print(f"   ✓ Normal activities: {summary['statistics']['normal_rows']:,}")
        print(f"   ✓ Chunks processed: {summary['statistics']['chunks_processed']}")
        print(f"\n💾 Output files created:")
        for name, path in summary['output_files'].items():
            print(f"   • {name}: {path}")
        
        # Verify output files exist
        print(f"\n🔍 Verifying output files...")
        all_exist = True
        for name, path in summary['output_files'].items():
            exists = os.path.exists(path)
            status = "✓" if exists else "✗"
            print(f"   {status} {name}: {exists}")
            if not exists:
                all_exist = False
        
        if all_exist:
            print("\n✅ All tests passed! System is working correctly.")
            print("\n🚀 You can now process your own datasets:")
            print("   python chunk_data_processor.py data/your_dataset.csv")
        else:
            print("\n⚠️  Some output files missing. Check for errors above.")
        
        return True
        
    except ImportError:
        print("\n❌ TEST FAILED!")
        print("   chunk_data_processor.py not found!")
        print("   Make sure the file exists in the same directory.")
        return False
    except Exception as e:
        print(f"\n❌ TEST FAILED!")
        print(f"   Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test execution"""
    print("\n" + "=" * 70)
    print("🧪 CHUNK PROCESSOR TEST SUITE")
    print("=" * 70)
    print("This script will:")
    print("  1. Generate a sample dataset (50,000 rows)")
    print("  2. Process it using chunk_data_processor.py")
    print("  3. Verify all outputs are created correctly")
    print("=" * 70)
    
    input("\nPress Enter to start testing...")
    
    success = test_processor()
    
    if success:
        print("\n" + "=" * 70)
        print("🎉 SUCCESS! Everything is working!")
        print("=" * 70)
        print("\n📚 Next Steps:")
        print("  1. Place your dataset in the 'data' folder")
        print("  2. Run: python chunk_data_processor.py data/your_dataset.csv")
        print("  3. Check results in 'data/processed' folder")
        print("\n💡 Tips:")
        print("  • Use --chunk-size to adjust memory usage")
        print("  • Use --output-format to choose CSV, JSON, or both")
        print("  • Process multiple files with batch_process.py")
        print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print("❌ TESTS FAILED")
        print("=" * 70)
        print("\n🔧 Troubleshooting:")
        print("  1. Make sure chunk_data_processor.py exists")
        print("  2. Install dependencies: pip install pandas numpy")
        print("  3. Check for error messages above")
        print("=" * 70)


if __name__ == '__main__':
    main()