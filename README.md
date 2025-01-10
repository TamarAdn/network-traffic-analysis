# Network Traffic Analysis Tool
This tool analyzes network traffic patterns from PCAP files to detect potential scanning behavior. It focuses on identifying sources that connect to an unusually high number of unique destinations, which might indicate network scanning or reconnaissance activity.

## Features

- Analyzes PCAP files for source-destination IP patterns
- Detects potential scanning behavior based on connection patterns
- Generates visual analysis including:
  - Top 10 most active source IPs
  - Distribution of connections per source IP
- Provides detailed reports of detected anomalies
- Asynchronous processing for efficient handling of large PCAP files

## Requirements

- Python 3.7+
- pyshark
- matplotlib
- nest_asyncio

Install required packages using:
```bash
pip install pyshark matplotlib nest_asyncio
```

## Usage

1. Capture network traffic using Wireshark and save as a PCAP file
2. Place the PCAP file in the same directory as the script
3. Run the script:
```bash
python analyze_traffic.py
```

The script will:
- Analyze the PCAP file
- Generate a report of findings
- Create visualizations of the traffic patterns
- Save the visualization as 'ip_pattern_analysis.png'

## Configuration

You can adjust the scanning threshold by modifying the `threshold` parameter when initializing the `IPPatternAnalyzer`:

```python
analyzer = IPPatternAnalyzer(
    file_path='network_traffic.pcap',
    threshold=100  # Adjust this value based on your network's normal behavior
)
```

## Output

The tool generates:
1. Console output with analysis results
2. Log file with processing details
3. Visualization file (ip_pattern_analysis.png) showing:
   - Bar chart of top source IPs
   - Distribution of connections with anomaly threshold

## Contributing

Feel free to open issues or submit pull requests with improvements.

## License

[MIT License](LICENSE)