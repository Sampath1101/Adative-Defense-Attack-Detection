"""
Large Dataset Chunk Processor for IDS Training
Processes large CSV/XLSX files in chunks to avoid memory issues
"""

import pandas as pd
import numpy as np
import os
import json
from datetime import datetime
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ChunkDataProcessor:
    """Process large datasets in chunks for memory efficiency"""
    
    def __init__(self, chunk_size=10000):
        """
        Initialize chunk processor
        
        Args:
            chunk_size (int): Number of rows per chunk
        """
        self.chunk_size = chunk_size
        self.data_dir = Path('data')
        self.output_dir = Path('data/processed')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics tracking
        self.stats = {
            'total_rows': 0,
            'suspicious_rows': 0,
            'normal_rows': 0,
            'chunks_processed': 0,
            'errors': 0
        }
    
    def detect_file_type(self, filepath):
        """Detect if file is CSV or Excel"""
        ext = Path(filepath).suffix.lower()
        if ext == '.csv':
            return 'csv'
        elif ext in ['.xlsx', '.xls']:
            return 'excel'
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    
    def read_chunks(self, filepath):
        """
        Read file in chunks
        
        Args:
            filepath (str): Path to input file
            
        Yields:
            pd.DataFrame: Chunk of data
        """
        file_type = self.detect_file_type(filepath)
        
        logger.info(f"📖 Reading file: {filepath}")
        logger.info(f"📊 File type: {file_type}")
        logger.info(f"📦 Chunk size: {self.chunk_size:,} rows")
        
        if file_type == 'csv':
            # Read CSV in chunks
            chunk_iterator = pd.read_csv(
                filepath,
                chunksize=self.chunk_size,
                encoding='utf-8',
                low_memory=False,
                on_bad_lines='skip'
            )
            
            for chunk in chunk_iterator:
                yield chunk
                
        elif file_type == 'excel':
            # For Excel, read entire file but process in chunks
            # (Excel doesn't support native chunking)
            logger.warning("⚠️  Excel files loaded entirely into memory first")
            df = pd.read_excel(filepath)
            
            # Split into chunks
            num_chunks = len(df) // self.chunk_size + 1
            for i in range(num_chunks):
                start_idx = i * self.chunk_size
                end_idx = min((i + 1) * self.chunk_size, len(df))
                yield df.iloc[start_idx:end_idx]
    
    def analyze_chunk(self, chunk):
        """
        Analyze a chunk for suspicious activity
        
        Args:
            chunk (pd.DataFrame): Data chunk
            
        Returns:
            dict: Analysis results
        """
        results = {
            'suspicious': [],
            'normal': [],
            'stats': {
                'total': len(chunk),
                'suspicious': 0,
                'normal': 0
            }
        }
        
        for idx, row in chunk.iterrows():
            is_suspicious, reasons = self.is_suspicious_activity(row)
            
            record = row.to_dict()
            record['analysis_timestamp'] = datetime.now().isoformat()
            
            if is_suspicious:
                record['suspicious'] = True
                record['reasons'] = reasons
                record['risk_level'] = self.calculate_risk_level(reasons)
                results['suspicious'].append(record)
                results['stats']['suspicious'] += 1
            else:
                record['suspicious'] = False
                results['normal'].append(record)
                results['stats']['normal'] += 1
        
        return results
    
    def is_suspicious_activity(self, row):
        """
        Check if a row contains suspicious activity
        
        Args:
            row (pd.Series): Data row
            
        Returns:
            tuple: (is_suspicious, reasons_list)
        """
        reasons = []
        
        # Convert row to dict for easier access
        data = row.to_dict()
        
        # Check for common suspicious patterns
        suspicious_patterns = {
            # SQL Injection patterns
            'sql_injection': [
                "'", "\"", "--", "/*", "*/", "xp_", "sp_",
                "union", "select", "insert", "update", "delete",
                "drop", "exec", "execute", "script", "javascript",
                "or 1=1", "or '1'='1", "'; drop", "admin' --"
            ],
            
            # XSS patterns
            'xss': [
                "<script", "<iframe", "onerror=", "onload=",
                "javascript:", "alert(", "document.cookie",
                "<img src=x", "eval(", "<object"
            ],
            
            # Path traversal
            'path_traversal': [
                "../", "..\\", "etc/passwd", "etc\\passwd",
                "windows\\system32", "/etc/shadow", "boot.ini"
            ],
            
            # Command injection
            'command_injection': [
                "|", "&&", "||", ";", "`", "$(", "${",
                "whoami", "ping", "curl", "wget", "nc ",
                "/bin/bash", "cmd.exe"
            ],
            
            # Admin/sensitive paths
            'admin_access': [
                "/admin", "/administrator", "/.env", "/config",
                "/backup", "/.git", "/wp-admin", "/phpmyadmin",
                "/console", "/manager"
            ]
        }
        
        # Check URL/Path field
        path_fields = ['path', 'url', 'request', 'uri', 'endpoint']
        for field in path_fields:
            if field in data and pd.notna(data[field]):
                path_str = str(data[field]).lower()
                
                for pattern_type, patterns in suspicious_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in path_str:
                            reasons.append(f"{pattern_type.replace('_', ' ').title()}: '{pattern}' detected in {field}")
                            break
        
        # Check HTTP method
        if 'method' in data and pd.notna(data['method']):
            method = str(data['method']).upper()
            if method in ['DELETE', 'PUT', 'TRACE', 'CONNECT']:
                reasons.append(f"Unusual HTTP method: {method}")
        
        # Check status code
        if 'status_code' in data and pd.notna(data['status_code']):
            status = int(data['status_code'])
            if status >= 400:
                reasons.append(f"Error status code: {status}")
        
        # Check response size (unusually large)
        if 'response_size' in data and pd.notna(data['response_size']):
            size = float(data['response_size'])
            if size > 1000000:  # > 1MB
                reasons.append(f"Large response size: {size:,.0f} bytes")
        
        # Check request frequency (if timestamp available)
        if 'timestamp' in data and hasattr(self, 'last_request_times'):
            ip = data.get('ip', data.get('source_ip', 'unknown'))
            current_time = pd.to_datetime(data['timestamp'])
            
            if ip in self.last_request_times:
                time_diff = (current_time - self.last_request_times[ip]).total_seconds()
                if time_diff < 1:  # Less than 1 second
                    reasons.append(f"Rapid requests: {time_diff:.2f}s interval")
            
            self.last_request_times[ip] = current_time
        
        # Check user agent
        if 'user_agent' in data and pd.notna(data['user_agent']):
            ua = str(data['user_agent']).lower()
            suspicious_agents = [
                'sqlmap', 'nikto', 'nmap', 'masscan', 'burp',
                'metasploit', 'havij', 'acunetix', 'nessus',
                'scanner', 'bot', 'crawler', 'scraper'
            ]
            for agent in suspicious_agents:
                if agent in ua:
                    reasons.append(f"Suspicious user agent: {agent}")
                    break
        
        # Check payload size
        if 'payload_size' in data and pd.notna(data['payload_size']):
            size = float(data['payload_size'])
            if size > 100000:  # > 100KB payload
                reasons.append(f"Large payload: {size:,.0f} bytes")
        
        return len(reasons) > 0, reasons
    
    def calculate_risk_level(self, reasons):
        """
        Calculate risk level based on reasons
        
        Args:
            reasons (list): List of suspicious reasons
            
        Returns:
            str: Risk level (high, medium, low)
        """
        high_risk_keywords = ['sql', 'xss', 'command', 'injection', 'drop', 'exec']
        medium_risk_keywords = ['admin', 'traversal', 'error', 'unusual']
        
        reasons_str = ' '.join(reasons).lower()
        
        high_count = sum(1 for kw in high_risk_keywords if kw in reasons_str)
        medium_count = sum(1 for kw in medium_risk_keywords if kw in reasons_str)
        
        if high_count >= 2 or len(reasons) >= 5:
            return 'high'
        elif high_count >= 1 or medium_count >= 2 or len(reasons) >= 3:
            return 'medium'
        else:
            return 'low'
    
    def process_file(self, filepath, output_format='csv'):
        """
        Process entire file in chunks
        
        Args:
            filepath (str): Path to input file
            output_format (str): Output format ('csv', 'json', or 'both')
        """
        logger.info("=" * 70)
        logger.info("🚀 Starting Large Dataset Processing")
        logger.info("=" * 70)
        
        start_time = datetime.now()
        self.last_request_times = {}  # Track request times for rate limiting
        
        # Output files
        suspicious_csv = self.output_dir / 'suspicious_activity.csv'
        normal_csv = self.output_dir / 'normal_activity.csv'
        suspicious_json = self.output_dir / 'suspicious_activity.json'
        summary_json = self.output_dir / 'analysis_summary.json'
        
        # Initialize output files
        suspicious_list = []
        normal_list = []
        
        chunk_num = 0
        
        try:
            for chunk in self.read_chunks(filepath):
                chunk_num += 1
                logger.info(f"\n📦 Processing Chunk {chunk_num}...")
                logger.info(f"   Rows in chunk: {len(chunk):,}")
                
                # Analyze chunk
                results = self.analyze_chunk(chunk)
                
                # Update statistics
                self.stats['total_rows'] += results['stats']['total']
                self.stats['suspicious_rows'] += results['stats']['suspicious']
                self.stats['normal_rows'] += results['stats']['normal']
                self.stats['chunks_processed'] = chunk_num
                
                # Collect results
                suspicious_list.extend(results['suspicious'])
                normal_list.extend(results['normal'])
                
                # Log progress
                logger.info(f"   ✓ Suspicious: {results['stats']['suspicious']}")
                logger.info(f"   ✓ Normal: {results['stats']['normal']}")
                logger.info(f"   📊 Total processed: {self.stats['total_rows']:,}")
                
                # Save intermediate results every 10 chunks
                if chunk_num % 10 == 0:
                    logger.info(f"\n💾 Saving intermediate results...")
                    self._save_results(
                        suspicious_list, normal_list,
                        suspicious_csv, normal_csv, suspicious_json,
                        output_format
                    )
            
            # Final save
            logger.info("\n💾 Saving final results...")
            self._save_results(
                suspicious_list, normal_list,
                suspicious_csv, normal_csv, suspicious_json,
                output_format
            )
            
            # Save summary
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            summary = {
                'processing_started': start_time.isoformat(),
                'processing_completed': end_time.isoformat(),
                'duration_seconds': duration,
                'input_file': str(filepath),
                'statistics': self.stats,
                'detection_rate': {
                    'suspicious_percentage': (self.stats['suspicious_rows'] / self.stats['total_rows'] * 100) 
                                            if self.stats['total_rows'] > 0 else 0,
                    'normal_percentage': (self.stats['normal_rows'] / self.stats['total_rows'] * 100) 
                                        if self.stats['total_rows'] > 0 else 0
                },
                'output_files': {
                    'suspicious_csv': str(suspicious_csv),
                    'normal_csv': str(normal_csv),
                    'suspicious_json': str(suspicious_json),
                    'summary': str(summary_json)
                }
            }
            
            with open(summary_json, 'w') as f:
                json.dump(summary, f, indent=2)
            
            # Print final summary
            self._print_summary(summary, duration)
            
            return summary
            
        except Exception as e:
            logger.error(f"❌ Error processing file: {str(e)}")
            self.stats['errors'] += 1
            raise
    
    def _save_results(self, suspicious_list, normal_list, 
                     suspicious_csv, normal_csv, suspicious_json,
                     output_format):
        """Save results to files"""
        
        if output_format in ['csv', 'both'] and suspicious_list:
            # Save suspicious activities
            df_suspicious = pd.DataFrame(suspicious_list)
            df_suspicious.to_csv(suspicious_csv, index=False)
            logger.info(f"   ✓ Saved: {suspicious_csv}")
            
        if output_format in ['csv', 'both'] and normal_list:
            # Save normal activities (sample if too large)
            if len(normal_list) > 50000:
                logger.info(f"   ℹ️  Normal activities > 50k, sampling 50k records")
                normal_sample = np.random.choice(
                    len(normal_list), 
                    size=min(50000, len(normal_list)), 
                    replace=False
                )
                df_normal = pd.DataFrame([normal_list[i] for i in normal_sample])
            else:
                df_normal = pd.DataFrame(normal_list)
            
            df_normal.to_csv(normal_csv, index=False)
            logger.info(f"   ✓ Saved: {normal_csv}")
        
        if output_format in ['json', 'both'] and suspicious_list:
            # Save suspicious as JSON
            with open(suspicious_json, 'w') as f:
                json.dump(suspicious_list, f, indent=2)
            logger.info(f"   ✓ Saved: {suspicious_json}")
    
    def _print_summary(self, summary, duration):
        """Print processing summary"""
        logger.info("\n" + "=" * 70)
        logger.info("✅ PROCESSING COMPLETE!")
        logger.info("=" * 70)
        logger.info(f"⏱️  Duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")
        logger.info(f"📊 Total Rows: {self.stats['total_rows']:,}")
        logger.info(f"🔴 Suspicious: {self.stats['suspicious_rows']:,} ({summary['detection_rate']['suspicious_percentage']:.2f}%)")
        logger.info(f"🟢 Normal: {self.stats['normal_rows']:,} ({summary['detection_rate']['normal_percentage']:.2f}%)")
        logger.info(f"📦 Chunks Processed: {self.stats['chunks_processed']}")
        logger.info(f"⚡ Processing Speed: {self.stats['total_rows']/duration:.0f} rows/second")
        logger.info("\n📁 Output Files:")
        for name, path in summary['output_files'].items():
            logger.info(f"   • {name}: {path}")
        logger.info("=" * 70)


def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Process large datasets in chunks for IDS analysis'
    )
    parser.add_argument(
        'input_file',
        help='Path to input CSV or Excel file'
    )
    parser.add_argument(
        '--chunk-size',
        type=int,
        default=10000,
        help='Number of rows per chunk (default: 10000)'
    )
    parser.add_argument(
        '--output-format',
        choices=['csv', 'json', 'both'],
        default='both',
        help='Output format (default: both)'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input_file):
        logger.error(f"❌ File not found: {args.input_file}")
        return
    
    # Process file
    processor = ChunkDataProcessor(chunk_size=args.chunk_size)
    
    try:
        summary = processor.process_file(
            args.input_file,
            output_format=args.output_format
        )
        
        logger.info("\n✅ Success! Check the 'data/processed' folder for results.")
        
    except Exception as e:
        logger.error(f"\n❌ Processing failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()