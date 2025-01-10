# Network Traffic Analysis Tool
# This script analyzes PCAP files to detect potential network scanning behavior
# by monitoring source-destination IP patterns

import pyshark                
import matplotlib.pyplot as plt   
import logging              
from collections import defaultdict   
from typing import Dict, List, Tuple  
import asyncio               
import nest_asyncio        
import os                  

# Fix for running async code in Jupyter/VS Code environments
nest_asyncio.apply()

# Configure logging to track errors and important events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IPPatternAnalyzer:
    """
    A class to analyze network traffic patterns and detect potential scanning behavior.
    It tracks IP patterns and identifies sources connecting to many unique destinations.
    """
    
    def __init__(self, file_path: str, threshold: int = 100):
        """
        Initialize the analyzer with a PCAP file and detection threshold.
        
        Args:
            file_path (str): Path to the PCAP file
            threshold (int): Number of unique destinations that indicates suspicious behavior
        """
        self.file_path = file_path
        self.threshold = threshold
        # Dictionary to store source-destination pair frequencies
        self.ip_patterns: Dict[Tuple[str, str], int] = defaultdict(int)
        # Dictionaries to track individual IP activities
        self.source_counts: Dict[str, int] = defaultdict(int)
        self.dest_counts: Dict[str, int] = defaultdict(int)
        # List to store detected anomalies
        self.anomalies: List[Tuple[str, str, int]] = []

    async def process_packet(self, packet) -> None:
        """
        Process a single packet asynchronously to extract IP information.
        
        Args:
            packet: A pyshark packet object containing network data
        """
        try:
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Increment counters for this source-destination pair
                self.ip_patterns[(src_ip, dst_ip)] += 1
                
                # Update individual IP counts
                self.source_counts[src_ip] += 1
                self.dest_counts[dst_ip] += 1
                
        except AttributeError as e:
            logging.warning(f"Skipping packet: {str(e)}")

    async def analyze_traffic_async(self) -> None:
        """
        Analyze the PCAP file asynchronously to process all packets.
        This method handles the main analysis workflow.
        """
        try:
            capture = pyshark.FileCapture(self.file_path)
            packet_count = 0

            # Process each packet in the capture
            for packet in capture:
                packet_count += 1
                # Print progress every 1000 packets
                if packet_count % 1000 == 0:
                    print(f"Processed {packet_count} packets...")
                
                await self.process_packet(packet)

            print(f"Finished processing {packet_count} packets")
            self._detect_anomalies()
            
        except FileNotFoundError:
            logging.error(f"PCAP file not found: {self.file_path}")
            raise
        except Exception as e:
            logging.error(f"Error during analysis: {str(e)}")
            raise
        finally:
            # Ensure proper cleanup of resources
            if 'capture' in locals():
                capture.close()

    def analyze_traffic(self) -> None:
        """
        Synchronous wrapper for the async analysis method.
        This provides a simple interface for running the analysis.
        """
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.analyze_traffic_async())

    def _detect_anomalies(self) -> None:
        """
        Identify sources showing potential scanning behavior based on
        the number of unique destinations they connect to.
        """
        for src_ip, count in self.source_counts.items():
            # Count how many unique destinations this source contacted
            unique_destinations = len([pair for pair in self.ip_patterns.keys() 
                                    if pair[0] == src_ip])
            # Flag if it exceeds our threshold
            if unique_destinations > self.threshold:
                self.anomalies.append((
                    src_ip,
                    "scanning",
                    unique_destinations
                ))

    def generate_report(self) -> None:
        """
        Generate and print a summary report of the analysis results,
        including statistics and detected anomalies.
        """
        print("\n=== IP Pattern Analysis Report ===")
        print(f"\nTotal unique source IPs: {len(self.source_counts)}")
        print(f"Total unique destination IPs: {len(self.dest_counts)}")
        print(f"\nAnomalies detected: {len(self.anomalies)}")
        
        if self.anomalies:
            print("\nDetailed Anomalies:")
            for ip, behavior, count in self.anomalies:
                print(f"IP: {ip} - Potential {behavior} behavior")
                print(f"Connected to {count} unique destinations")
                print(f"Threshold: {self.threshold}")

    def visualize_data(self) -> None:
        """
        Create visualizations of the traffic patterns and anomalies.
        Generates two plots:
        1. Top 10 most active source IPs
        2. Distribution of connections per source IP
        """
        if not self.source_counts:
            print("No data to visualize!")
            return

        plt.figure(figsize=(15, 6))

        # First subplot: Bar chart of top source IPs
        plt.subplot(1, 2, 1)
        top_sources = sorted(self.source_counts.items(), 
                           key=lambda x: x[1], 
                           reverse=True)[:10]
        ips, counts = zip(*top_sources)
        plt.bar(range(len(ips)), counts)
        plt.title('Top 10 Source IPs by Connection Count')
        plt.xlabel('Source IP')
        plt.ylabel('Number of Connections')
        plt.xticks(range(len(ips)), 
                  [f"...{ip[-8:]}" for ip in ips], 
                  rotation=45)

        # Second subplot: Distribution histogram
        plt.subplot(1, 2, 2)
        connection_counts = list(self.source_counts.values())
        plt.hist(connection_counts, bins=30, edgecolor='black')
        plt.axvline(self.threshold, color='red', 
                   linestyle='dashed', 
                   label='Anomaly Threshold')
        plt.title('Distribution of Connections per Source IP')
        plt.xlabel('Number of Connections')
        plt.ylabel('Frequency')
        plt.legend()

        plt.tight_layout()
        print("Saving figure...")
        plt.savefig('ip_pattern_analysis.png')
        print("Displaying plot...")
        plt.show()

def main():
    """
    Main entry point of the script.
    Sets up the analyzer and runs the analysis workflow.
    """
    # Verify input file exists
    file_path = 'network_traffic.pcap'
    if not os.path.exists(file_path):
        print(f"Error: Cannot find PCAP file at {file_path}")
        print(f"Current working directory: {os.getcwd()}")
        return

    print("Starting analysis...")
    analyzer = IPPatternAnalyzer(
        file_path=file_path,
        threshold=100  # Adjust this threshold based on your network's normal behavior
    )
    
    try:
        analyzer.analyze_traffic()
        analyzer.generate_report()
        analyzer.visualize_data()
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()